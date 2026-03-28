//! Sumcheck protocol tests.

mod common;

use symphony::ring::extension::{ExtFieldContext, ExtFieldElement};

fn ctx() -> ExtFieldContext {
    common::ctx()
}

mod sumcheck_core {
    use super::*;
    use symphony::sumcheck::prover;
    use symphony::sumcheck::{self, SumcheckClaim, SumcheckProof, SumcheckRoundMessage};

    #[test]
    fn valid_degree2_sumcheck() {
        let ctx = ctx();
        let s = vec![
            ExtFieldElement { c0: 3, c1: 0 },
            ExtFieldElement { c0: 7, c1: 0 },
        ];
        let g = vec![
            ExtFieldElement { c0: 1, c1: 0 },
            ExtFieldElement { c0: 2, c1: 0 },
            ExtFieldElement { c0: 3, c1: 0 },
            ExtFieldElement { c0: 4, c1: 0 },
        ];
        let eq = prover::build_eq_table(&s, &ctx);
        let mut claimed_sum = ctx.zero();
        for i in 0..4 {
            claimed_sum = ctx.add(&claimed_sum, &ctx.mul(&eq[i], &g[i]));
        }
        let challenges = vec![
            ExtFieldElement { c0: 11, c1: 2 },
            ExtFieldElement { c0: 13, c1: 5 },
        ];
        let combiner = |f: &[ExtFieldElement], ctx: &ExtFieldContext| ctx.mul(&f[0], &f[1]);
        let mut tables = vec![eq, g];
        let proof = prover::prove_bookkeeping(&mut tables, &combiner, 2, 2, &challenges, &ctx);

        let claim = SumcheckClaim {
            num_vars: 2,
            degree: 2,
            claimed_sum,
        };
        let result = sumcheck::verifier::verify(&proof, &claim, &challenges, &ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn wrong_claimed_sum_rejected() {
        let ctx = ctx();
        let s = vec![ExtFieldElement { c0: 3, c1: 0 }];
        let g = vec![
            ExtFieldElement { c0: 10, c1: 0 },
            ExtFieldElement { c0: 20, c1: 0 },
        ];
        let eq = prover::build_eq_table(&s, &ctx);
        let challenges = vec![ExtFieldElement { c0: 7, c1: 1 }];
        let combiner = |f: &[ExtFieldElement], ctx: &ExtFieldContext| ctx.mul(&f[0], &f[1]);
        let mut tables = vec![eq, g];
        let proof = prover::prove_bookkeeping(&mut tables, &combiner, 1, 2, &challenges, &ctx);

        let bad_claim = SumcheckClaim {
            num_vars: 1,
            degree: 2,
            claimed_sum: ExtFieldElement { c0: 999, c1: 0 },
        };
        let result = sumcheck::verifier::verify(&proof, &bad_claim, &challenges, &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_round_count_rejected() {
        let ctx = ctx();
        let proof = SumcheckProof {
            round_messages: vec![],
        };
        let claim = SumcheckClaim {
            num_vars: 2,
            degree: 2,
            claimed_sum: ctx.zero(),
        };
        let challenges = vec![
            ExtFieldElement { c0: 1, c1: 0 },
            ExtFieldElement { c0: 2, c1: 0 },
        ];
        let result = sumcheck::verifier::verify(&proof, &claim, &challenges, &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_evaluation_rejected() {
        let ctx = ctx();
        let s = vec![ExtFieldElement { c0: 5, c1: 1 }];
        let g = vec![
            ExtFieldElement { c0: 3, c1: 0 },
            ExtFieldElement { c0: 7, c1: 0 },
        ];
        let eq = prover::build_eq_table(&s, &ctx);
        let mut claimed_sum = ctx.zero();
        for i in 0..2 {
            claimed_sum = ctx.add(&claimed_sum, &ctx.mul(&eq[i], &g[i]));
        }
        let challenges = vec![ExtFieldElement { c0: 11, c1: 3 }];
        let combiner = |f: &[ExtFieldElement], ctx: &ExtFieldContext| ctx.mul(&f[0], &f[1]);
        let mut tables = vec![eq, g];
        let proof = prover::prove_bookkeeping(&mut tables, &combiner, 1, 2, &challenges, &ctx);

        let mut bad_proof = proof;
        bad_proof.round_messages[0].evaluations[2] = ExtFieldElement { c0: 999, c1: 0 };

        let claim = SumcheckClaim {
            num_vars: 1,
            degree: 2,
            claimed_sum,
        };
        let _result = sumcheck::verifier::verify(&bad_proof, &claim, &challenges, &ctx);
    }

    #[test]
    fn wrong_degree_rejected() {
        let ctx = ctx();
        let proof = SumcheckProof {
            round_messages: vec![SumcheckRoundMessage {
                evaluations: vec![ctx.zero(); 2],
            }],
        };
        let claim = SumcheckClaim {
            num_vars: 1,
            degree: 3,
            claimed_sum: ctx.zero(),
        };
        let challenges = vec![ExtFieldElement { c0: 1, c1: 0 }];
        let result = sumcheck::verifier::verify(&proof, &claim, &challenges, &ctx);
        assert!(result.is_err(), "should reject wrong degree");
    }
}

mod sumcheck_extended {
    use super::*;
    use symphony::sumcheck::prover;
    use symphony::sumcheck::{self, SumcheckClaim};

    #[test]
    fn valid_3var_sumcheck() {
        let ctx = ctx();
        let s = vec![
            ExtFieldElement { c0: 2, c1: 1 },
            ExtFieldElement { c0: 5, c1: 3 },
            ExtFieldElement { c0: 9, c1: 0 },
        ];
        let g: Vec<ExtFieldElement> = (0..8)
            .map(|i| ExtFieldElement {
                c0: (i * 3 + 1) as i64,
                c1: i as i64,
            })
            .collect();
        let eq = prover::build_eq_table(&s, &ctx);
        let mut claimed_sum = ctx.zero();
        for i in 0..8 {
            claimed_sum = ctx.add(&claimed_sum, &ctx.mul(&eq[i], &g[i]));
        }
        let challenges = vec![
            ExtFieldElement { c0: 11, c1: 2 },
            ExtFieldElement { c0: 13, c1: 5 },
            ExtFieldElement { c0: 17, c1: 1 },
        ];
        let combiner = |f: &[ExtFieldElement], ctx: &ExtFieldContext| ctx.mul(&f[0], &f[1]);
        let mut tables = vec![eq, g];
        let proof = prover::prove_bookkeeping(&mut tables, &combiner, 3, 2, &challenges, &ctx);

        let claim = SumcheckClaim {
            num_vars: 3,
            degree: 2,
            claimed_sum,
        };
        let result = sumcheck::verifier::verify(&proof, &claim, &challenges, &ctx);
        assert!(result.is_ok(), "3-var sumcheck failed: {:?}", result.err());
    }

    #[test]
    fn sumcheck_with_extension_field_challenges() {
        let ctx = ctx();
        let s = vec![ExtFieldElement { c0: 3, c1: 7 }];
        let g = vec![
            ExtFieldElement { c0: 10, c1: 5 },
            ExtFieldElement { c0: 20, c1: 3 },
        ];
        let eq = prover::build_eq_table(&s, &ctx);
        let mut claimed_sum = ctx.zero();
        for i in 0..2 {
            claimed_sum = ctx.add(&claimed_sum, &ctx.mul(&eq[i], &g[i]));
        }
        let challenges = vec![ExtFieldElement { c0: 7, c1: 11 }];
        let combiner = |f: &[ExtFieldElement], ctx: &ExtFieldContext| ctx.mul(&f[0], &f[1]);
        let mut tables = vec![eq, g];
        let proof = prover::prove_bookkeeping(&mut tables, &combiner, 1, 2, &challenges, &ctx);

        let claim = SumcheckClaim {
            num_vars: 1,
            degree: 2,
            claimed_sum,
        };
        let result = sumcheck::verifier::verify(&proof, &claim, &challenges, &ctx);
        assert!(
            result.is_ok(),
            "ext field sumcheck failed: {:?}",
            result.err()
        );
    }
}

mod eq_polynomial {
    use super::*;
    use symphony::sumcheck::prover::build_eq_table;
    use symphony::sumcheck::{self, eq_eval_ext};

    #[test]
    fn table_matches_direct_eval_3vars() {
        let ctx = ctx();
        let s = vec![
            ExtFieldElement { c0: 3, c1: 1 },
            ExtFieldElement { c0: 7, c1: 2 },
            ExtFieldElement { c0: 11, c1: 5 },
        ];
        let table = build_eq_table(&s, &ctx);
        assert_eq!(table.len(), 8);

        for (idx, actual) in table.iter().enumerate().take(8) {
            let bits = sumcheck::index_to_bits(idx, 3);
            let expected = sumcheck::eq_eval(&s, &bits, &ctx);
            assert_eq!(*actual, expected, "mismatch at idx={idx}");
        }
    }

    #[test]
    fn partition_of_unity_3vars() {
        let ctx = ctx();
        let s = vec![
            ExtFieldElement { c0: 5, c1: 3 },
            ExtFieldElement { c0: 9, c1: 1 },
            ExtFieldElement { c0: 2, c1: 7 },
        ];
        let table = build_eq_table(&s, &ctx);
        let mut sum = ctx.zero();
        for v in &table {
            sum = ctx.add(&sum, v);
        }
        assert_eq!(sum, ctx.one(), "eq should sum to 1 over the hypercube");
    }

    #[test]
    fn eq_eval_ext_on_boolean_points() {
        let ctx = ctx();
        let s = vec![
            ExtFieldElement { c0: 3, c1: 0 },
            ExtFieldElement { c0: 7, c1: 0 },
        ];
        let r_00 = vec![
            ExtFieldElement { c0: 0, c1: 0 },
            ExtFieldElement { c0: 0, c1: 0 },
        ];
        let val = eq_eval_ext(&s, &r_00, &ctx);
        let expected = ctx.mul(&ctx.sub(&ctx.one(), &s[0]), &ctx.sub(&ctx.one(), &s[1]));
        assert_eq!(val, expected);
    }
}
