//! Folding scheme tests: high-arity folding, streaming prover, two-layer folding.

mod common;

use common::Q;
use symphony::commitment::AjtaiParams;
use symphony::params::D;
use symphony::ring::extension::ExtFieldContext;
use symphony::ring::ntt::NttContext;
use symphony::ring::{RingElement, RingVector};

fn ctx() -> ExtFieldContext {
    common::ctx()
}

mod folding {
    use super::*;
    use symphony::folding::{self, FoldingStatement};
    use symphony::rok::range_proof::RangeProofParams;

    fn range_params() -> RangeProofParams {
        RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        }
    }

    // Build a FoldingStatement: commit to the full z, then split into
    // public_input and witness-only part.
    fn make_statement(z: &[i64], n_in: usize, ajtai: &AjtaiParams) -> FoldingStatement {
        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = ajtai.commit(&full_ring);
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        FoldingStatement {
            commitment: c,
            public_input: z[..n_in].to_vec(),
            witness: witness_part,
        }
    }

    #[test]
    fn fold_two_statements() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q, &ntt);

        let s1 = make_statement(&z, n_in, &ajtai);
        let s2 = make_statement(&z, n_in, &ajtai);
        let pi1 = s1.public_input.clone();
        let pi2 = s2.public_input.clone();
        let stmts = vec![s1, s2];

        let rp = range_params();
        let (proof, folded_w, _) = folding::prove(&stmts, &r1cs, &ajtai, &rp, &ctx);

        assert_eq!(proof.gr1cs_proofs.len(), 2);
        assert_eq!(proof.beta.len(), 2);
        assert!(!folded_w.witness.is_empty());

        let public_inputs = vec![pi1, pi2];
        let result = folding::verify(&proof, &public_inputs, &r1cs, &ajtai, &rp, &ctx);
        assert!(result.is_ok(), "Folding verify failed: {:?}", result.err());
    }

    #[test]
    fn folded_public_input_is_consistent() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q, &ntt);

        let s1 = make_statement(&z, n_in, &ajtai);
        let s2 = make_statement(&z, n_in, &ajtai);
        let stmts = vec![s1, s2];

        let rp = range_params();
        let (proof, _, _) = folding::prove(&stmts, &r1cs, &ajtai, &rp, &ctx);

        // Folded public input[i] = Σ β[ℓ] · cf^{-1}(x_in[i])
        for (i, &z_i) in z.iter().enumerate().take(n_in) {
            let x_ring = RingElement::from_constant(z_i);
            let term0 = x_ring.mul(&proof.beta[0], Q);
            let term1 = x_ring.mul(&proof.beta[1], Q);
            let expected = term0.add(&term1, Q);
            assert_eq!(proof.folded_instance.public_input[i], expected);
        }
    }

    #[test]
    fn challenge_set_properties() {
        use symphony::folding::challenge::ChallengeSet;
        let cs = ChallengeSet::new(Q);
        let mut rng = rand::rng();
        for _ in 0..50 {
            let s = cs.sample(&mut rng);
            assert!(ChallengeSet::is_in_set(&s), "sampled element not in set");
            assert!(s.norm_inf() <= 2, "coefficient out of {{0,±1,±2}}");
            assert!(
                ChallengeSet::operator_norm_bound() <= 15,
                "operator norm too large"
            );
        }
    }

    #[test]
    fn challenge_differences_have_bounded_norm() {
        use symphony::folding::challenge::ChallengeSet;
        let cs = ChallengeSet::new(Q);
        let mut rng = rand::rng();
        for _ in 0..20 {
            let a = cs.sample(&mut rng);
            let b = cs.sample(&mut rng);
            let diff = a.sub(&b, Q);
            assert!(
                ChallengeSet::is_in_difference_set(&diff),
                "difference not in S-S"
            );
        }
    }
}

mod folding_extended {
    use super::*;
    use symphony::folding::{self, FoldingStatement};
    use symphony::rok::range_proof::RangeProofParams;

    fn range_params() -> RangeProofParams {
        RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        }
    }

    fn make_statement(z: &[i64], n_in: usize, ajtai: &AjtaiParams) -> FoldingStatement {
        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = ajtai.commit(&full_ring);
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        FoldingStatement {
            commitment: c,
            public_input: z[..n_in].to_vec(),
            witness: witness_part,
        }
    }

    #[test]
    fn fold_three_statements() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q, &ntt);

        let stmts: Vec<_> = (0..3).map(|_| make_statement(&z, n_in, &ajtai)).collect();
        let pis: Vec<Vec<i64>> = stmts.iter().map(|s| s.public_input.clone()).collect();

        let rp = range_params();
        let (proof, folded_w, _) = folding::prove(&stmts, &r1cs, &ajtai, &rp, &ctx);

        assert_eq!(proof.gr1cs_proofs.len(), 3);
        assert_eq!(proof.beta.len(), 3);
        assert!(!folded_w.witness.is_empty());

        let result = folding::verify(&proof, &pis, &r1cs, &ajtai, &rp, &ctx);
        assert!(
            result.is_ok(),
            "3-statement fold failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn folded_witness_length_preserved() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let n_w = r1cs.num_variables - n_in;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q, &ntt);

        let stmts: Vec<_> = (0..2).map(|_| make_statement(&z, n_in, &ajtai)).collect();
        let rp = range_params();
        let (_, folded_w, _) = folding::prove(&stmts, &r1cs, &ajtai, &rp, &ctx);

        assert_eq!(folded_w.witness.len(), n_w);
    }

    #[test]
    fn folded_commitment_length_matches_kappa() {
        let ctx = ctx();
        let kappa = 3;
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(kappa, r1cs.num_variables, Q, &ntt);

        let stmts: Vec<_> = (0..2).map(|_| make_statement(&z, n_in, &ajtai)).collect();
        let rp = range_params();
        let (proof, _, _) = folding::prove(&stmts, &r1cs, &ajtai, &rp, &ctx);

        assert_eq!(proof.folded_instance.commitment.value.len(), kappa);
    }
}

mod streaming {
    use super::*;
    use symphony::commitment::AjtaiParams;
    use symphony::folding::streaming::{StreamingPhase, StreamingProver};

    #[test]
    fn full_lifecycle() {
        let n = 4;
        let ell_np = 3;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, n, Q, &ntt);
        let mut prover = StreamingProver::new(ajtai, ell_np);
        prover.set_ext_context(ctx());

        let witnesses: Vec<RingVector> = (1..=ell_np as i64)
            .map(|v| RingVector {
                elements: vec![RingElement::from_constant(v); n],
            })
            .collect();

        // Commitment phase
        for w in &witnesses {
            prover.feed_witness_commitment(w);
        }
        assert!(matches!(prover.phase(), StreamingPhase::Sumcheck { .. }));

        // Sumcheck passes
        while matches!(prover.phase(), StreamingPhase::Sumcheck { .. }) {
            for (i, w) in witnesses.iter().enumerate() {
                prover.feed_witness_sumcheck(w, i);
            }
        }
        assert_eq!(prover.phase(), StreamingPhase::Folding);

        // Folding phase
        for (i, w) in witnesses.iter().enumerate() {
            prover.feed_witness_folding(w, i);
        }
        assert_eq!(prover.phase(), StreamingPhase::Complete);

        let result = prover.finish();
        assert_eq!(result.witness.len(), n);
    }
}

mod streaming_extended {
    use super::*;
    use symphony::folding::streaming::{StreamingPhase, StreamingProver};

    #[test]
    fn single_statement() {
        let n = 2;
        let ell_np = 1;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, n, Q, &ntt);
        let mut prover = StreamingProver::new(ajtai, ell_np);
        prover.set_ext_context(ctx());

        let w = RingVector {
            elements: vec![RingElement::from_constant(5); n],
        };

        prover.feed_witness_commitment(&w);
        assert!(matches!(prover.phase(), StreamingPhase::Sumcheck { .. }));

        while matches!(prover.phase(), StreamingPhase::Sumcheck { .. }) {
            prover.feed_witness_sumcheck(&w, 0);
        }
        assert_eq!(prover.phase(), StreamingPhase::Folding);

        prover.feed_witness_folding(&w, 0);
        assert_eq!(prover.phase(), StreamingPhase::Complete);

        let result = prover.finish();
        assert_eq!(result.witness.len(), n);
    }

    #[test]
    fn five_statements() {
        let n = 4;
        let ell_np = 5;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, n, Q, &ntt);
        let mut prover = StreamingProver::new(ajtai, ell_np);
        prover.set_ext_context(ctx());

        let witnesses: Vec<RingVector> = (1..=ell_np as i64)
            .map(|v| RingVector {
                elements: vec![RingElement::from_constant(v); n],
            })
            .collect();

        for w in &witnesses {
            prover.feed_witness_commitment(w);
        }

        while matches!(prover.phase(), StreamingPhase::Sumcheck { .. }) {
            for (i, w) in witnesses.iter().enumerate() {
                prover.feed_witness_sumcheck(w, i);
            }
        }

        for (i, w) in witnesses.iter().enumerate() {
            prover.feed_witness_folding(w, i);
        }

        assert_eq!(prover.phase(), StreamingPhase::Complete);
        let result = prover.finish();
        assert_eq!(result.witness.len(), n);
    }

    #[test]
    fn streaming_ring_mul_and_ext_accumulation() {
        use symphony::ring::extension::ExtFieldContext;
        let n = 4;
        let ell_np = 2;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, n, Q, &ntt);
        let mut prover = StreamingProver::new(ajtai, ell_np);
        prover.set_ext_context(ExtFieldContext::new(Q));

        // Witnesses with non-trivial polynomial coefficients (not just constants)
        let w1 = RingVector {
            elements: vec![RingElement::monomial(1); n],
        };
        let w2 = RingVector {
            elements: vec![RingElement::monomial(2); n],
        };

        prover.feed_witness_commitment(&w1);
        prover.feed_witness_commitment(&w2);

        while matches!(prover.phase(), StreamingPhase::Sumcheck { .. }) {
            prover.feed_witness_sumcheck(&w1, 0);
            prover.feed_witness_sumcheck(&w2, 1);
        }
        assert_eq!(prover.phase(), StreamingPhase::Folding);

        prover.feed_witness_folding(&w1, 0);
        prover.feed_witness_folding(&w2, 1);

        assert_eq!(prover.phase(), StreamingPhase::Complete);
        let result = prover.finish();
        assert_eq!(result.witness.len(), n);

        let is_all_zero = result
            .witness
            .elements
            .iter()
            .all(|e| e.coeffs.iter().all(|&c| c == 0));
        assert!(
            !is_all_zero,
            "folded witness should not be all zeros with monomial inputs"
        );
    }
}

mod streaming_integer_log {
    use super::*;
    use symphony::folding::streaming::{StreamingPhase, StreamingProver};

    #[test]
    fn streaming_with_various_witness_sizes() {
        for &n in &[1usize, 2, 4, 8, 16] {
            let ell_np = 2;
            let ntt = NttContext::new(Q);
            let ajtai = AjtaiParams::setup(2, n, Q, &ntt);
            let mut prover = StreamingProver::new(ajtai, ell_np);
            prover.set_ext_context(ctx());

            let w1 = RingVector {
                elements: vec![RingElement::from_constant(1); n],
            };
            let w2 = RingVector {
                elements: vec![RingElement::from_constant(2); n],
            };

            prover.feed_witness_commitment(&w1);
            prover.feed_witness_commitment(&w2);
            assert!(
                matches!(prover.phase(), StreamingPhase::Sumcheck { .. }),
                "should enter sumcheck phase for n={n}"
            );

            while matches!(prover.phase(), StreamingPhase::Sumcheck { .. }) {
                prover.feed_witness_sumcheck(&w1, 0);
                prover.feed_witness_sumcheck(&w2, 1);
            }
            assert_eq!(prover.phase(), StreamingPhase::Folding);

            prover.feed_witness_folding(&w1, 0);
            prover.feed_witness_folding(&w2, 1);
            assert_eq!(prover.phase(), StreamingPhase::Complete);

            let result = prover.finish();
            assert_eq!(result.witness.len(), n);
        }
    }
}

mod projection_seed_fix {
    use super::*;
    use symphony::folding::{self, FoldingStatement};
    use symphony::rok::range_proof::RangeProofParams;

    fn range_params() -> RangeProofParams {
        RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        }
    }

    #[test]
    fn different_commitments_produce_different_proofs() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q, &ntt);

        // Statement 1: z = [1, 3, 9]
        let mk = |z_vals: &[i64]| {
            let full_ring = RingVector {
                elements: z_vals
                    .iter()
                    .map(|&v| RingElement::from_constant(v))
                    .collect(),
            };
            let (c, _) = ajtai.commit(&full_ring);
            let witness_part = RingVector {
                elements: z_vals[n_in..]
                    .iter()
                    .map(|&v| RingElement::from_constant(v))
                    .collect(),
            };
            FoldingStatement {
                commitment: c,
                public_input: z_vals[..n_in].to_vec(),
                witness: witness_part,
            }
        };

        let stmts1 = vec![mk(&z), mk(&z)];
        let pis1: Vec<Vec<i64>> = stmts1.iter().map(|s| s.public_input.clone()).collect();

        // Use different witnesses for a second proof (still satisfying R1CS)
        let z2 = vec![1i64, 4, 16]; // 4*4 = 16
        let stmts2 = vec![mk(&z2), mk(&z2)];
        let pis2: Vec<Vec<i64>> = stmts2.iter().map(|s| s.public_input.clone()).collect();

        let rp = range_params();
        let (proof1, _, _) = folding::prove(&stmts1, &r1cs, &ajtai, &rp, &ctx);
        let (proof2, _, _) = folding::prove(&stmts2, &r1cs, &ajtai, &rp, &ctx);

        // The projection seed is transcript-derived, so different commitments
        // should lead to different GR1CS proofs
        let p1_bytes: Vec<u8> = proof1.gr1cs_proofs[0]
            .hadamard_proof
            .sumcheck_proof
            .round_messages
            .iter()
            .flat_map(|m| m.evaluations.iter().flat_map(|e| e.c0.to_le_bytes()))
            .collect();
        let p2_bytes: Vec<u8> = proof2.gr1cs_proofs[0]
            .hadamard_proof
            .sumcheck_proof
            .round_messages
            .iter()
            .flat_map(|m| m.evaluations.iter().flat_map(|e| e.c0.to_le_bytes()))
            .collect();
        assert_ne!(
            p1_bytes, p2_bytes,
            "different witnesses should produce different proof data"
        );

        // Both should still verify
        let r1 = folding::verify(&proof1, &pis1, &r1cs, &ajtai, &rp, &ctx);
        let r2 = folding::verify(&proof2, &pis2, &r1cs, &ajtai, &rp, &ctx);
        assert!(r1.is_ok(), "proof1 verification failed: {:?}", r1.err());
        assert!(r2.is_ok(), "proof2 verification failed: {:?}", r2.err());
    }
}

mod transcript_binding_fix {
    use super::*;
    use symphony::folding::{self, FoldingStatement};
    use symphony::rok::range_proof::RangeProofParams;

    fn range_params() -> RangeProofParams {
        RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        }
    }

    #[test]
    fn folding_beta_depends_on_proof_content() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q, &ntt);

        let mk = |z_vals: &[i64]| {
            let full_ring = RingVector {
                elements: z_vals
                    .iter()
                    .map(|&v| RingElement::from_constant(v))
                    .collect(),
            };
            let (c, _) = ajtai.commit(&full_ring);
            let witness_part = RingVector {
                elements: z_vals[n_in..]
                    .iter()
                    .map(|&v| RingElement::from_constant(v))
                    .collect(),
            };
            FoldingStatement {
                commitment: c,
                public_input: z_vals[..n_in].to_vec(),
                witness: witness_part,
            }
        };

        let rp = range_params();

        // Two different valid statements
        let stmts_a = vec![mk(&z), mk(&z)];
        let z2 = vec![1i64, 4, 16];
        let stmts_b = vec![mk(&z2), mk(&z2)];

        let (proof_a, _, _) = folding::prove(&stmts_a, &r1cs, &ajtai, &rp, &ctx);
        let (proof_b, _, _) = folding::prove(&stmts_b, &r1cs, &ajtai, &rp, &ctx);

        // Because GR1CS proofs are now bound to the transcript before β is
        // derived, different proofs should yield different β vectors.
        assert_ne!(
            proof_a.beta.iter().map(|b| b.coeffs).collect::<Vec<_>>(),
            proof_b.beta.iter().map(|b| b.coeffs).collect::<Vec<_>>(),
            "β should differ when proof content differs"
        );
    }
}

mod eval_folding_ring_mul {
    use super::*;
    use symphony::folding::{self, FoldingStatement};
    use symphony::rok::range_proof::RangeProofParams;

    fn range_params() -> RangeProofParams {
        RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        }
    }

    #[test]
    fn folded_eval_values_are_nonempty() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q, &ntt);

        let mk = |z_vals: &[i64]| {
            let full_ring = RingVector {
                elements: z_vals
                    .iter()
                    .map(|&v| RingElement::from_constant(v))
                    .collect(),
            };
            let (c, _) = ajtai.commit(&full_ring);
            let witness_part = RingVector {
                elements: z_vals[n_in..]
                    .iter()
                    .map(|&v| RingElement::from_constant(v))
                    .collect(),
            };
            FoldingStatement {
                commitment: c,
                public_input: z_vals[..n_in].to_vec(),
                witness: witness_part,
            }
        };

        let stmts = vec![mk(&z), mk(&z)];
        let rp = range_params();
        let (proof, _, _) = folding::prove(&stmts, &r1cs, &ajtai, &rp, &ctx);

        assert!(
            !proof.folded_instance.evaluation_values.is_empty(),
            "folded evaluation values should not be empty"
        );

        // With ring mul folding, evaluation values should generally be
        // non-trivial (not all zeros) when β is non-trivial.
        let all_zero = proof
            .folded_instance
            .evaluation_values
            .iter()
            .all(|te| te.data.iter().all(|row| row.iter().all(|&v| v == 0)));
        assert!(!all_zero, "folded eval values should not all be zero");
    }

    #[test]
    fn folded_eval_values_use_ring_structure() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q, &ntt);

        let mk = |z_vals: &[i64]| {
            let full_ring = RingVector {
                elements: z_vals
                    .iter()
                    .map(|&v| RingElement::from_constant(v))
                    .collect(),
            };
            let (c, _) = ajtai.commit(&full_ring);
            let witness_part = RingVector {
                elements: z_vals[n_in..]
                    .iter()
                    .map(|&v| RingElement::from_constant(v))
                    .collect(),
            };
            FoldingStatement {
                commitment: c,
                public_input: z_vals[..n_in].to_vec(),
                witness: witness_part,
            }
        };

        let stmts = vec![mk(&z), mk(&z)];
        let pis: Vec<Vec<i64>> = stmts.iter().map(|s| s.public_input.clone()).collect();
        let rp = range_params();
        let (proof, _, _) = folding::prove(&stmts, &r1cs, &ajtai, &rp, &ctx);

        // The verifier should still accept with ring-mul-based folding
        let result = folding::verify(&proof, &pis, &r1cs, &ajtai, &rp, &ctx);
        assert!(
            result.is_ok(),
            "folding with ring mul eval folding should verify: {:?}",
            result.err()
        );
    }
}

mod folding_soundness {
    use super::*;
    use symphony::folding::{self, FoldingStatement};
    use symphony::rok::range_proof::RangeProofParams;

    fn range_params() -> RangeProofParams {
        RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        }
    }

    fn make_statement(z: &[i64], n_in: usize, ajtai: &AjtaiParams) -> FoldingStatement {
        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = ajtai.commit(&full_ring);
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        FoldingStatement {
            commitment: c,
            public_input: z[..n_in].to_vec(),
            witness: witness_part,
        }
    }

    #[test]
    fn tampered_commitment_rejected() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q, &ntt);

        let stmts: Vec<_> = (0..2).map(|_| make_statement(&z, n_in, &ajtai)).collect();
        let pis: Vec<Vec<i64>> = stmts.iter().map(|s| s.public_input.clone()).collect();

        let rp = range_params();
        let (mut proof, _, _) = folding::prove(&stmts, &r1cs, &ajtai, &rp, &ctx);

        // Tamper with the folded commitment
        proof.folded_instance.commitment.value.elements[0] = RingElement::from_constant(999);

        let result = folding::verify(&proof, &pis, &r1cs, &ajtai, &rp, &ctx);
        assert!(
            result.is_err(),
            "tampered folded commitment should be rejected"
        );
    }

    #[test]
    fn mismatched_public_input_count_rejected() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q, &ntt);

        let stmts: Vec<_> = (0..2).map(|_| make_statement(&z, n_in, &ajtai)).collect();

        let rp = range_params();
        let (proof, _, _) = folding::prove(&stmts, &r1cs, &ajtai, &rp, &ctx);

        // Provide only 1 public input instead of 2
        let wrong_pis = vec![z[..n_in].to_vec()];
        let result = folding::verify(&proof, &wrong_pis, &r1cs, &ajtai, &rp, &ctx);
        assert!(
            result.is_err(),
            "mismatched public input count should be rejected"
        );
    }

    #[test]
    fn tampered_beta_rejected() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q, &ntt);

        let stmts: Vec<_> = (0..2).map(|_| make_statement(&z, n_in, &ajtai)).collect();
        let pis: Vec<Vec<i64>> = stmts.iter().map(|s| s.public_input.clone()).collect();

        let rp = range_params();
        let (mut proof, _, _) = folding::prove(&stmts, &r1cs, &ajtai, &rp, &ctx);

        // Tamper with the beta challenge vector
        proof.beta[0] = RingElement::from_constant(42);

        let result = folding::verify(&proof, &pis, &r1cs, &ajtai, &rp, &ctx);
        assert!(
            result.is_err(),
            "tampered beta should be rejected by verifier"
        );
    }
}

mod two_layer {
    use super::*;
    use symphony::folding::two_layer::{self, TwoLayerParams};
    use symphony::folding::FoldingStatement;
    use symphony::rok::range_proof::RangeProofParams;

    #[test]
    fn prove_verify() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n = r1cs.num_variables;
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, n, Q, &ntt);

        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        let (c1, _) = ajtai.commit(&full_ring);
        let (c2, _) = ajtai.commit(&full_ring);

        let stmts = vec![
            FoldingStatement {
                commitment: c1,
                public_input: z[..n_in].to_vec(),
                witness: witness_part.clone(),
            },
            FoldingStatement {
                commitment: c2,
                public_input: z[..n_in].to_vec(),
                witness: witness_part,
            },
        ];

        let rp = RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        };
        let two_params = TwoLayerParams {
            num_blocks: 1,
            decomp_base: 16,
            k_b: 2,
            block_scalars: vec![RingElement::from_constant(1)],
        };

        let (proof, folded_w) =
            two_layer::prove_two_layer(&stmts, &r1cs, &ajtai, &rp, &two_params, &ctx);
        assert!(!folded_w.witness.is_empty());

        let public_inputs: Vec<Vec<i64>> = stmts.iter().map(|s| s.public_input.clone()).collect();
        let result = two_layer::verify_two_layer(
            &proof,
            &public_inputs,
            &r1cs,
            &ajtai,
            &rp,
            &two_params,
            &ctx,
        );
        assert!(
            result.is_ok(),
            "Two-layer verify failed: {:?}",
            result.err()
        );
    }
}

mod two_layer_consistency_fix {
    use super::*;
    use symphony::folding::two_layer::{self, TwoLayerParams};
    use symphony::folding::FoldingStatement;
    use symphony::rok::range_proof::RangeProofParams;

    #[test]
    fn cross_layer_commitment_verified() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n = r1cs.num_variables;
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, n, Q, &ntt);

        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        let (c1, _) = ajtai.commit(&full_ring);
        let (c2, _) = ajtai.commit(&full_ring);

        let stmts = vec![
            FoldingStatement {
                commitment: c1,
                public_input: z[..n_in].to_vec(),
                witness: witness_part.clone(),
            },
            FoldingStatement {
                commitment: c2,
                public_input: z[..n_in].to_vec(),
                witness: witness_part,
            },
        ];
        let pis: Vec<Vec<i64>> = stmts.iter().map(|s| s.public_input.clone()).collect();

        let rp = RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        };
        let tp = TwoLayerParams {
            num_blocks: 1,
            decomp_base: 16,
            k_b: 2,
            block_scalars: vec![RingElement::from_constant(1)],
        };

        let (proof, _) = two_layer::prove_two_layer(&stmts, &r1cs, &ajtai, &rp, &tp, &ctx);

        // Verify that layer1_instance matches what layer1 folding produced
        let result = two_layer::verify_two_layer(&proof, &pis, &r1cs, &ajtai, &rp, &tp, &ctx);
        assert!(
            result.is_ok(),
            "cross-layer consistency check should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn tampered_layer1_instance_rejected() {
        let ctx = ctx();
        let (r1cs, z) = common::simple_r1cs();
        let n = r1cs.num_variables;
        let n_in = r1cs.num_public;
        let ntt = NttContext::new(Q);
        let ajtai = AjtaiParams::setup(2, n, Q, &ntt);

        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        let (c1, _) = ajtai.commit(&full_ring);
        let (c2, _) = ajtai.commit(&full_ring);

        let stmts = vec![
            FoldingStatement {
                commitment: c1,
                public_input: z[..n_in].to_vec(),
                witness: witness_part.clone(),
            },
            FoldingStatement {
                commitment: c2,
                public_input: z[..n_in].to_vec(),
                witness: witness_part,
            },
        ];
        let pis: Vec<Vec<i64>> = stmts.iter().map(|s| s.public_input.clone()).collect();

        let rp = RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        };
        let tp = TwoLayerParams {
            num_blocks: 1,
            decomp_base: 16,
            k_b: 2,
            block_scalars: vec![RingElement::from_constant(1)],
        };

        let (mut proof, _) = two_layer::prove_two_layer(&stmts, &r1cs, &ajtai, &rp, &tp, &ctx);

        // Tamper with the layer1 instance commitment
        proof.layer1_instance.commitment.value.elements[0] = RingElement::from_constant(999);

        let result = two_layer::verify_two_layer(&proof, &pis, &r1cs, &ajtai, &rp, &tp, &ctx);
        assert!(
            result.is_err(),
            "tampered layer1_instance should be rejected by cross-layer check"
        );
    }
}
