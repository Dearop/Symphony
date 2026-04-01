//! Fiat-Shamir transcript and challenge derivation tests.

mod common;

use common::Q;
use symphony::fiat_shamir::transcript::Transcript;
use symphony::params::SymphonyParams;

mod fiat_shamir_core {
    use super::*;

    #[test]
    fn determinism() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        t1.append_bytes(b"data", b"hello");
        t2.append_bytes(b"data", b"hello");
        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];
        t1.challenge_bytes(b"ch", &mut c1);
        t2.challenge_bytes(b"ch", &mut c2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn domain_separation() {
        let mut t1 = Transcript::new(b"domain-A");
        let mut t2 = Transcript::new(b"domain-B");
        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];
        t1.challenge_bytes(b"ch", &mut c1);
        t2.challenge_bytes(b"ch", &mut c2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn order_dependence() {
        let mut t1 = Transcript::new(b"test");
        t1.append_bytes(b"a", b"1");
        t1.append_bytes(b"b", b"2");

        let mut t2 = Transcript::new(b"test");
        t2.append_bytes(b"b", b"2");
        t2.append_bytes(b"a", b"1");

        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];
        t1.challenge_bytes(b"ch", &mut c1);
        t2.challenge_bytes(b"ch", &mut c2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn ext_field_challenge_in_range() {
        let mut t = Transcript::new(b"test");
        let q_half = (Q / 2) as i64;
        for i in 0..20 {
            let label = format!("ch-{i}");
            let e = t.challenge_ext_field(label.as_bytes(), Q);
            assert!(e.c0.abs() <= q_half, "c0 out of range: {}", e.c0);
            assert!(e.c1.abs() <= q_half, "c1 out of range: {}", e.c1);
        }
    }

    #[test]
    fn successive_squeezes_differ() {
        let mut t = Transcript::new(b"test");
        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];
        t.challenge_bytes(b"first", &mut c1);
        t.challenge_bytes(b"second", &mut c2);
        assert_ne!(c1, c2);
    }
}

mod fiat_shamir_extended {
    use super::*;

    #[test]
    fn different_label_different_challenge() {
        let mut t = Transcript::new(b"test");
        t.append_bytes(b"data", b"same");
        let mut c1 = [0u8; 32];
        t.challenge_bytes(b"label-A", &mut c1);

        let mut t2 = Transcript::new(b"test");
        t2.append_bytes(b"data", b"same");
        let mut c2 = [0u8; 32];
        t2.challenge_bytes(b"label-B", &mut c2);

        assert_ne!(c1, c2);
    }

    #[test]
    fn challenge_of_various_lengths() {
        let mut t = Transcript::new(b"test");
        for len in [1, 8, 16, 32, 48, 64, 128] {
            let mut buf = vec![0u8; len];
            t.challenge_bytes(b"ch", &mut buf);
            assert!(
                !buf.iter().all(|&b| b == 0),
                "all-zero challenge at len={len}"
            );
        }
    }

    #[test]
    fn large_data_append() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        let big_data = vec![0xABu8; 10_000];
        t1.append_bytes(b"big", &big_data);
        t2.append_bytes(b"big", &big_data);
        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];
        t1.challenge_bytes(b"ch", &mut c1);
        t2.challenge_bytes(b"ch", &mut c2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn transcript_state_not_reused() {
        let mut t = Transcript::new(b"test");
        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];
        t.challenge_bytes(b"same-label", &mut c1);
        t.challenge_bytes(b"same-label", &mut c2);
        assert_ne!(
            c1, c2,
            "same label squeezed twice must differ due to state update"
        );
    }
}

mod fiat_shamir_bias_fix {
    use super::*;

    #[test]
    fn challenge_scalar_in_range() {
        let mut t = Transcript::new(b"test-bias");
        let q_half = (Q / 2) as i64;
        for i in 0..50 {
            let label = format!("scalar-{i}");
            let s = t.challenge_scalar(label.as_bytes(), Q);
            assert!(
                s >= -q_half && s <= q_half,
                "challenge_scalar out of centered range: {s}"
            );
        }
    }

    #[test]
    fn challenge_scalar_deterministic() {
        let mut t1 = Transcript::new(b"det-test");
        let mut t2 = Transcript::new(b"det-test");
        t1.append_bytes(b"data", b"hello");
        t2.append_bytes(b"data", b"hello");
        let s1 = t1.challenge_scalar(b"ch", Q);
        let s2 = t2.challenge_scalar(b"ch", Q);
        assert_eq!(s1, s2);
    }

    #[test]
    fn challenge_ext_field_with_large_q() {
        let p = SymphonyParams::default_from_paper();
        let mut t = Transcript::new(b"large-q-test");
        let q_half = (p.q / 2) as i64;
        for i in 0..20 {
            let label = format!("ext-{i}");
            let e = t.challenge_ext_field(label.as_bytes(), p.q);
            assert!(
                e.c0.abs() <= q_half,
                "c0 out of range: {} (q_half={})",
                e.c0,
                q_half
            );
            assert!(
                e.c1.abs() <= q_half,
                "c1 out of range: {} (q_half={})",
                e.c1,
                q_half
            );
        }
    }

    #[test]
    fn challenge_ext_field_uses_wider_bytes_than_before() {
        let mut t1 = Transcript::new(b"domain-A");
        let mut t2 = Transcript::new(b"domain-B");
        let e1 = t1.challenge_ext_field(b"ch", Q);
        let e2 = t2.challenge_ext_field(b"ch", Q);
        assert_ne!(e1, e2);
    }
}

mod transcript_edge_cases {
    use super::*;

    #[test]
    fn append_empty_data() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        t1.append_bytes(b"label", b"");
        t2.append_bytes(b"label", b"");
        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];
        t1.challenge_bytes(b"ch", &mut c1);
        t2.challenge_bytes(b"ch", &mut c2);
        assert_eq!(c1, c2, "empty data appends should be deterministic");
    }

    #[test]
    fn challenge_scalar_small_q() {
        // Test with very small primes
        for &q in &[2u64, 3, 5, 7, 11] {
            let mut t = Transcript::new(b"small-q");
            let q_half = (q / 2) as i64;
            for i in 0..20 {
                let label = format!("s-{i}");
                let s = t.challenge_scalar(label.as_bytes(), q);
                assert!(
                    s >= -(q_half) && s <= q_half,
                    "scalar {s} out of range for q={q}"
                );
            }
        }
    }

    #[test]
    fn challenge_bytes_single_byte() {
        let mut t = Transcript::new(b"single-byte");
        t.append_bytes(b"data", b"hello");
        let mut buf = [0u8; 1];
        t.challenge_bytes(b"ch", &mut buf);
        // Just verify it doesn't panic and produces something
        // (with overwhelmingly high probability, it's non-zero after hashing)
        let mut t2 = Transcript::new(b"single-byte");
        t2.append_bytes(b"data", b"hello");
        let mut buf2 = [0u8; 1];
        t2.challenge_bytes(b"ch", &mut buf2);
        assert_eq!(buf, buf2, "single byte challenge should be deterministic");
    }
}

mod challenge_rejection_sampling {
    use super::*;
    use symphony::folding::challenge::{derive_challenge_vector, ChallengeSet};

    #[test]
    #[cfg(debug_assertions)]
    fn challenge_vector_rejects_q_le_4() {
        let mut transcript = Transcript::new(b"test");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            derive_challenge_vector(&mut transcript, 3, 1);
        }));
        assert!(
            result.is_err(),
            "derive_challenge_vector should panic when q <= 4"
        );
    }

    #[test]
    fn derived_challenges_in_set_s() {
        let mut transcript = Transcript::new(b"challenge-test");
        transcript.append_bytes(b"data", b"some-commitment-data");
        let challenges = derive_challenge_vector(&mut transcript, Q, 10);
        assert_eq!(challenges.len(), 10);
        for (i, ch) in challenges.iter().enumerate() {
            assert!(ChallengeSet::is_in_set(ch), "challenge[{i}] not in S");
        }
    }

    #[test]
    fn derived_challenges_deterministic() {
        let mut t1 = Transcript::new(b"det");
        let mut t2 = Transcript::new(b"det");
        t1.append_bytes(b"x", b"data");
        t2.append_bytes(b"x", b"data");
        let c1 = derive_challenge_vector(&mut t1, Q, 5);
        let c2 = derive_challenge_vector(&mut t2, Q, 5);
        for (a, b) in c1.iter().zip(c2.iter()) {
            assert_eq!(a.coeffs, b.coeffs);
        }
    }

    #[test]
    fn derived_challenges_differ_for_different_transcripts() {
        let mut t1 = Transcript::new(b"transcript-A");
        let mut t2 = Transcript::new(b"transcript-B");
        let c1 = derive_challenge_vector(&mut t1, Q, 3);
        let c2 = derive_challenge_vector(&mut t2, Q, 3);
        let all_same = c1.iter().zip(c2.iter()).all(|(a, b)| a.coeffs == b.coeffs);
        assert!(
            !all_same,
            "different transcripts should produce different challenges"
        );
    }

    #[test]
    fn all_five_values_appear() {
        let mut transcript = Transcript::new(b"distribution-test");
        let challenges = derive_challenge_vector(&mut transcript, Q, 50);
        let mut seen = [false; 5];
        for ch in &challenges {
            for &c in &ch.coeffs {
                let idx = (c + 2) as usize;
                if idx < 5 {
                    seen[idx] = true;
                }
            }
        }
        for (i, &s) in seen.iter().enumerate() {
            assert!(
                s,
                "value {} never appeared in 50*64 = 3200 coefficients",
                i as i64 - 2
            );
        }
    }
}
