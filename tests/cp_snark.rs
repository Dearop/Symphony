//! Standalone CP-SNARK tests: HashCommitment, relations, builder.

use symphony::cp_snark::{CPSnark, CPSnarkBuilder, FnRelation, IdentityRelation, PreimageRelation, TranscriptRelation};
use symphony::fiat_shamir::hash_commitment::HashCommitment;
use symphony::fiat_shamir::FSCommitment;
use symphony::fiat_shamir::transcript::Transcript;
use symphony::snark::DummySnark;

mod hash_commitment_tests {
    use super::*;

    #[test]
    fn commit_verify_roundtrip() {
        let scheme = HashCommitment::new();
        let msg = b"hello world";
        let (c, o) = scheme.commit(msg);
        assert!(scheme.verify(&c, msg, &o));
    }

    #[test]
    fn wrong_message_rejected() {
        let scheme = HashCommitment::new();
        let (c, o) = scheme.commit(b"correct");
        assert!(!scheme.verify(&c, b"wrong", &o));
    }

    #[test]
    fn wrong_opening_rejected() {
        let scheme = HashCommitment::new();
        let (c, _o) = scheme.commit(b"data");
        let fake_opening = [0u8; 32];
        assert!(!scheme.verify(&c, b"data", &fake_opening));
    }

    #[test]
    fn different_messages_different_commitments() {
        let scheme = HashCommitment::new();
        let (c1, _) = scheme.commit(b"aaa");
        let (c2, _) = scheme.commit(b"bbb");
        assert_ne!(c1, c2);
    }

    #[test]
    fn same_message_different_randomness() {
        let scheme = HashCommitment::new();
        let (c1, _) = scheme.commit(b"same");
        let (c2, _) = scheme.commit(b"same");
        assert_ne!(c1, c2, "different randomness should produce different commitments");
    }

    #[test]
    fn empty_message() {
        let scheme = HashCommitment::new();
        let (c, o) = scheme.commit(b"");
        assert!(scheme.verify(&c, b"", &o));
        assert!(!scheme.verify(&c, b"x", &o));
    }

    #[test]
    fn large_message() {
        let scheme = HashCommitment::new();
        let msg = vec![0xABu8; 4096];
        let (c, o) = scheme.commit(&msg);
        assert!(scheme.verify(&c, &msg, &o));
    }
}

mod identity_relation {
    use super::*;

    #[test]
    fn single_message_prove_verify() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 32);
        let (c, o) = scheme.commit(b"secret");
        let proof = cp.prove(&scheme, &[b"secret".as_slice()], &[o], &[c], b"", &IdentityRelation).unwrap();
        assert!(cp.verify(&[c], b"", &proof));
    }

    #[test]
    fn multiple_messages() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(3, 32);
        let (c1, o1) = scheme.commit(b"alpha");
        let (c2, o2) = scheme.commit(b"beta");
        let (c3, o3) = scheme.commit(b"gamma");
        let proof = cp.prove(&scheme, &[b"alpha".as_slice(), b"beta", b"gamma"], &[o1, o2, o3], &[c1, c2, c3], b"pub-data", &IdentityRelation).unwrap();
        assert!(cp.verify(&[c1, c2, c3], b"pub-data", &proof));
    }

    #[test]
    fn wrong_commitment_count_verify_fails() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 16);
        let (c1, o1) = scheme.commit(b"a");
        let (c2, o2) = scheme.commit(b"b");
        let proof = cp.prove(&scheme, &[b"a".as_slice(), b"b"], &[o1, o2], &[c1, c2], b"", &IdentityRelation).unwrap();
        assert!(!cp.verify(&[c1], b"", &proof));
    }

    #[test]
    fn wrong_message_opening_rejected() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 32);
        let (c, _o) = scheme.commit(b"real");
        let (_, o_fake) = scheme.commit(b"fake");
        let result = cp.prove(&scheme, &[b"real".as_slice()], &[o_fake], &[c], b"", &IdentityRelation);
        assert!(result.is_none());
    }

    #[test]
    fn mismatched_lengths_rejected() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 16);
        let (c, o) = scheme.commit(b"x");
        assert!(cp.prove(&scheme, &[b"x".as_slice()], &[o], &[c], b"", &IdentityRelation).is_none());
    }
}

mod preimage_relation {
    use super::*;
    use sha2::{Sha256, Digest};

    fn hash_concat(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for p in parts { h.update(p); }
        h.finalize().into()
    }

    #[test]
    fn valid_preimage_accepted() {
        let scheme = HashCommitment::new();
        let m1 = b"foo";
        let m2 = b"bar";
        let digest = hash_concat(&[m1, m2]);
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 8);
        let (c1, o1) = scheme.commit(m1);
        let (c2, o2) = scheme.commit(m2);
        let proof = cp.prove(&scheme, &[m1.as_slice(), m2.as_slice()], &[o1, o2], &[c1, c2], &digest, &PreimageRelation).unwrap();
        assert!(cp.verify(&[c1, c2], &digest, &proof));
    }

    #[test]
    fn wrong_digest_rejected() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 16);
        let (c, o) = scheme.commit(b"data");
        let wrong = [0xFFu8; 32];
        assert!(cp.prove(&scheme, &[b"data".as_slice()], &[o], &[c], &wrong, &PreimageRelation).is_none());
    }

    #[test]
    fn single_message_preimage() {
        let scheme = HashCommitment::new();
        let msg = b"single";
        let digest = hash_concat(&[msg.as_slice()]);
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 16);
        let (c, o) = scheme.commit(msg);
        let proof = cp.prove(&scheme, &[msg.as_slice()], &[o], &[c], &digest, &PreimageRelation).unwrap();
        assert!(cp.verify(&[c], &digest, &proof));
    }
}

mod transcript_relation_tests {
    use super::*;

    #[test]
    fn valid_transcript_accepted() {
        let scheme = HashCommitment::new();
        let m1 = b"round-0-payload";
        let m2 = b"round-1-payload";
        let mut tr = Transcript::new(b"my-protocol");
        tr.append_bytes(b"round-0", m1);
        tr.append_bytes(b"round-1", m2);
        let mut expected = vec![0u8; 32];
        tr.challenge_bytes(b"relation-output", &mut expected);
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 32);
        let (c1, o1) = scheme.commit(m1);
        let (c2, o2) = scheme.commit(m2);
        let relation = TranscriptRelation { domain: b"my-protocol".to_vec() };
        let proof = cp.prove(&scheme, &[m1.as_slice(), m2.as_slice()], &[o1, o2], &[c1, c2], &expected, &relation).unwrap();
        assert!(cp.verify(&[c1, c2], &expected, &proof));
    }

    #[test]
    fn wrong_domain_rejected() {
        let scheme = HashCommitment::new();
        let m = b"data";
        let mut tr = Transcript::new(b"correct-domain");
        tr.append_bytes(b"round-0", m);
        let mut expected = vec![0u8; 32];
        tr.challenge_bytes(b"relation-output", &mut expected);
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 16);
        let (c, o) = scheme.commit(m);
        let wrong_relation = TranscriptRelation { domain: b"wrong-domain".to_vec() };
        assert!(cp.prove(&scheme, &[m.as_slice()], &[o], &[c], &expected, &wrong_relation).is_none());
    }

    #[test]
    fn empty_statement_accepted() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 16);
        let (c, o) = scheme.commit(b"x");
        let relation = TranscriptRelation { domain: b"d".to_vec() };
        let proof = cp.prove(&scheme, &[b"x".as_slice()], &[o], &[c], b"", &relation).unwrap();
        assert!(cp.verify(&[c], b"", &proof));
    }
}

mod fn_relation_tests {
    use super::*;

    #[test]
    fn sum_of_u64_values() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(3, 8);
        let vals: Vec<u64> = vec![10, 20, 70];
        let committed: Vec<_> = vals.iter().map(|v| scheme.commit(&v.to_le_bytes())).collect();
        let cs: Vec<_> = committed.iter().map(|(c, _)| *c).collect();
        let os: Vec<_> = committed.iter().map(|(_, o)| *o).collect();
        let msgs: Vec<Vec<u8>> = vals.iter().map(|v| v.to_le_bytes().to_vec()).collect();
        let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let sum_is_100 = FnRelation(|ms: &[&[u8]], _| {
            let s: u64 = ms.iter().map(|m| u64::from_le_bytes(m[..8].try_into().unwrap())).sum();
            s == 100
        });
        let proof = cp.prove(&scheme, &msg_refs, &os, &cs, b"", &sum_is_100).unwrap();
        assert!(cp.verify(&cs, b"", &proof));
    }

    #[test]
    fn product_relation() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 8);
        let a = 7u64;
        let b = 6u64;
        let (ca, oa) = scheme.commit(&a.to_le_bytes());
        let (cb, ob) = scheme.commit(&b.to_le_bytes());
        let expected_product = (a * b).to_le_bytes();
        let product_rel = FnRelation(|ms: &[&[u8]], stmt: &[u8]| {
            let x = u64::from_le_bytes(ms[0][..8].try_into().unwrap());
            let y = u64::from_le_bytes(ms[1][..8].try_into().unwrap());
            let expected = u64::from_le_bytes(stmt[..8].try_into().unwrap());
            x * y == expected
        });
        let proof = cp.prove(&scheme, &[&a.to_le_bytes(), &b.to_le_bytes()], &[oa, ob], &[ca, cb], &expected_product, &product_rel).unwrap();
        assert!(cp.verify(&[ca, cb], &expected_product, &proof));
    }

    #[test]
    fn failing_fn_relation() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 8);
        let (c, o) = scheme.commit(&5u64.to_le_bytes());
        let must_be_even = FnRelation(|ms: &[&[u8]], _| {
            let v = u64::from_le_bytes(ms[0][..8].try_into().unwrap());
            v % 2 == 0
        });
        assert!(cp.prove(&scheme, &[&5u64.to_le_bytes()], &[o], &[c], b"", &must_be_even).is_none());
    }

    #[test]
    fn string_containment_relation() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 64);
        let msg = b"the quick brown fox";
        let (c, o) = scheme.commit(msg);
        let contains_fox = FnRelation(|ms: &[&[u8]], _| {
            let s = std::str::from_utf8(ms[0]).unwrap_or("");
            s.contains("fox")
        });
        let proof = cp.prove(&scheme, &[msg.as_slice()], &[o], &[c], b"", &contains_fox).unwrap();
        assert!(cp.verify(&[c], b"", &proof));
    }
}

mod builder_tests {
    use super::*;

    #[test]
    fn builder_identity() {
        let scheme = HashCommitment::new();
        let (c1, o1) = scheme.commit(b"msg-a");
        let (c2, o2) = scheme.commit(b"msg-b");
        let (proof, commitments) = CPSnarkBuilder::<DummySnark, HashCommitment>::new()
            .message(b"msg-a", o1, c1)
            .message(b"msg-b", o2, c2)
            .statement(b"pub")
            .prove(&scheme, &IdentityRelation)
            .unwrap();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 5);
        assert!(cp.verify(&commitments, b"pub", &proof));
    }

    #[test]
    fn builder_commit_and_add() {
        let scheme = HashCommitment::new();
        let (proof, commitments) = CPSnarkBuilder::<DummySnark, HashCommitment>::new()
            .commit_and_add(&scheme, b"auto-1")
            .commit_and_add(&scheme, b"auto-2")
            .prove(&scheme, &IdentityRelation)
            .unwrap();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 6);
        assert!(cp.verify(&commitments, b"", &proof));
    }

    #[test]
    fn builder_preimage() {
        use sha2::{Sha256, Digest};
        let scheme = HashCommitment::new();
        let m1 = b"x";
        let m2 = b"y";
        let mut h = Sha256::new();
        h.update(m1);
        h.update(m2);
        let digest: [u8; 32] = h.finalize().into();
        let (c1, o1) = scheme.commit(m1);
        let (c2, o2) = scheme.commit(m2);
        let (proof, commitments) = CPSnarkBuilder::<DummySnark, HashCommitment>::new()
            .message(m1, o1, c1)
            .message(m2, o2, c2)
            .statement(&digest)
            .prove(&scheme, &PreimageRelation)
            .unwrap();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 1);
        assert!(cp.verify(&commitments, &digest, &proof));
    }
}

mod soundness_tests {
    use super::*;

    #[test]
    fn tampered_commitment_produces_different_transcript_digest() {
        let scheme = HashCommitment::new();
        let (c1, o1) = scheme.commit(b"msg-A");
        let (c2, o2) = scheme.commit(b"msg-B");
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 16);
        let p1 = cp.prove(&scheme, &[b"msg-A".as_slice()], &[o1], &[c1], b"", &IdentityRelation).unwrap();
        let p2 = cp.prove(&scheme, &[b"msg-B".as_slice()], &[o2], &[c2], b"", &IdentityRelation).unwrap();
        assert_ne!(p1.transcript_digest, p2.transcript_digest, "different commitments must produce different transcript digests");
    }

    #[test]
    fn different_public_statement_produces_different_transcript_digest() {
        let scheme = HashCommitment::new();
        let (c, o) = scheme.commit(b"data");
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 16);
        let p1 = cp.prove(&scheme, &[b"data".as_slice()], &[o], &[c], b"stmt-A", &IdentityRelation).unwrap();
        let p2 = cp.prove(&scheme, &[b"data".as_slice()], &[o], &[c], b"stmt-B", &IdentityRelation).unwrap();
        assert_ne!(p1.transcript_digest, p2.transcript_digest, "different public statements must produce different transcript digests");
    }

    #[test]
    fn zero_messages_setup() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(0, 0);
        let always_true = FnRelation(|_: &[&[u8]], _| true);
        let proof = cp.prove(&scheme, &[], &[], &[], b"ok", &always_true).unwrap();
        assert!(cp.verify(&[], b"ok", &proof));
    }

    #[test]
    fn large_message_count() {
        let scheme = HashCommitment::new();
        let n = 16;
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(n, 4);
        let committed: Vec<_> = (0..n).map(|i| scheme.commit(&(i as u32).to_le_bytes())).collect();
        let cs: Vec<_> = committed.iter().map(|(c, _)| *c).collect();
        let os: Vec<_> = committed.iter().map(|(_, o)| *o).collect();
        let msgs: Vec<Vec<u8>> = (0..n).map(|i| (i as u32).to_le_bytes().to_vec()).collect();
        let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let proof = cp.prove(&scheme, &msg_refs, &os, &cs, b"", &IdentityRelation).unwrap();
        assert!(cp.verify(&cs, b"", &proof));
    }

    #[test]
    fn proof_transcript_digest_is_deterministic() {
        let scheme = HashCommitment::new();
        let msg = b"deterministic";
        let (c, o) = scheme.commit(msg);
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 16);
        let p1 = cp.prove(&scheme, &[msg.as_slice()], &[o], &[c], b"s", &IdentityRelation).unwrap();
        let p2 = cp.prove(&scheme, &[msg.as_slice()], &[o], &[c], b"s", &IdentityRelation).unwrap();
        assert_eq!(p1.transcript_digest, p2.transcript_digest, "same inputs should produce identical transcript digests");
    }
}

mod pipeline_integration {
    use super::*;

    #[test]
    fn symphony_style_folding_transcript() {
        let scheme = HashCommitment::new();
        let round_msgs: Vec<Vec<u8>> = (0..4).map(|i| {
            format!("folding-round-{i}-data-with-sumcheck-evals").into_bytes()
        }).collect();
        let mut tr = Transcript::new(b"symphony-v1");
        for (i, msg) in round_msgs.iter().enumerate() {
            tr.append_bytes(format!("round-{i}").as_bytes(), msg);
        }
        let mut expected = vec![0u8; 32];
        tr.challenge_bytes(b"relation-output", &mut expected);
        let committed: Vec<_> = round_msgs.iter().map(|m| scheme.commit(m)).collect();
        let cs: Vec<_> = committed.iter().map(|(c, _)| *c).collect();
        let os: Vec<_> = committed.iter().map(|(_, o)| *o).collect();
        let msg_refs: Vec<&[u8]> = round_msgs.iter().map(|m| m.as_slice()).collect();
        let relation = TranscriptRelation { domain: b"symphony-v1".to_vec() };
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(4, 64);
        let proof = cp.prove(&scheme, &msg_refs, &os, &cs, &expected, &relation).unwrap();
        assert!(cp.verify(&cs, &expected, &proof));
    }

    #[test]
    fn transcript_relation_wrong_message_rejected() {
        let scheme = HashCommitment::new();
        let correct_msg = b"correct-round-data";
        let wrong_msg = b"tampered-round-data";
        let mut tr = Transcript::new(b"proto");
        tr.append_bytes(b"round-0", correct_msg);
        let mut expected = vec![0u8; 32];
        tr.challenge_bytes(b"relation-output", &mut expected);
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 32);
        let (c, o) = scheme.commit(wrong_msg);
        let relation = TranscriptRelation { domain: b"proto".to_vec() };
        assert!(cp.prove(&scheme, &[wrong_msg.as_slice()], &[o], &[c], &expected, &relation).is_none());
    }
}
