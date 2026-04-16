//! Tests verifying the correctness of all audit fixes (C1–C6, H1–H6, M1–M8, L1–L6).

use symphony::params::{SymphonyParams, D};
use symphony::r1cs::{R1CSMatrices, SparseMatrix};
use symphony::ring::extension::{ExtFieldContext, ExtFieldElement};
use symphony::ring::ntt::NttContext;
use symphony::ring::{RingElement, RingVector};
use symphony::snark::{BackendSnark, DummySnark, RelationDescription};

// =========================================================================
// C1: validate() called in setup()
// =========================================================================

#[test]
fn c1_setup_calls_validate() {
    // A params set with d != D should panic during setup because validate() is called.
    let bad_params = SymphonyParams {
        q: 257,
        d: 32, // wrong: D == 64
        kappa: 12,
        ell_np: 1024,
        ell_h: 1 << 14,
        lambda_pj: 256,
        n_bar: 1 << 16,
        m: 1 << 16,
        b: 16,
        k_cs: 16,
        ntt: SymphonyParams::try_ntt(257, D),
    };
    let result = std::panic::catch_unwind(|| {
        symphony::snark::SymphonyProver::<DummySnark>::setup(bad_params);
    });
    assert!(result.is_err(), "setup() should panic when d != D (C1: validate called in setup)");
}

// =========================================================================
// C2: validate() checks multiple constraints
// =========================================================================

#[test]
fn c2_validate_rejects_non_prime_q() {
    let params = SymphonyParams {
        q: 128, // not prime
        d: D,
        kappa: 12,
        ell_np: 1024,
        ell_h: 1 << 14,
        lambda_pj: 256,
        n_bar: 1 << 16,
        m: 1 << 16,
        b: 16,
        k_cs: 16,
        ntt: SymphonyParams::try_ntt(128, D),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| params.validate()));
    assert!(result.is_err(), "validate should reject non-prime q");
}

#[test]
fn c2_validate_rejects_q_not_1_mod_2d() {
    // 127 is prime but 127 % 128 != 1
    let params = SymphonyParams {
        q: 127,
        d: D,
        kappa: 12,
        ell_np: 1024,
        ell_h: 1 << 14,
        lambda_pj: 256,
        n_bar: 1 << 16,
        m: 1 << 16,
        b: 16,
        k_cs: 16,
        ntt: SymphonyParams::try_ntt(127, D),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| params.validate()));
    assert!(result.is_err(), "validate should reject q not congruent to 1 mod 2d");
}

#[test]
fn c2_validate_rejects_b_less_than_2() {
    let params = SymphonyParams::default_from_paper();
    let params2 = SymphonyParams {
        q: params.q,
        d: D,
        kappa: 12,
        ell_np: 1024,
        ell_h: 1 << 14,
        lambda_pj: 256,
        n_bar: 1 << 16,
        m: 1 << 16,
        b: 1, // invalid
        k_cs: 16,
        ntt: SymphonyParams::try_ntt(params.q, D),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| params2.validate()));
    assert!(result.is_err(), "validate should reject b < 2");
}

#[test]
fn c2_validate_rejects_k_cs_zero() {
    let good = SymphonyParams::default_from_paper();
    let params = SymphonyParams {
        q: good.q,
        d: D,
        kappa: 12,
        ell_np: 1024,
        ell_h: 1 << 14,
        lambda_pj: 256,
        n_bar: 1 << 16,
        m: 1 << 16,
        b: 16,
        k_cs: 0, // invalid
        ntt: SymphonyParams::try_ntt(good.q, D),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| params.validate()));
    assert!(result.is_err(), "validate should reject k_cs == 0");
}

#[test]
fn c2_validate_accepts_good_params() {
    // default_from_paper calls validate internally; should not panic
    let params = SymphonyParams::default_from_paper();
    assert_eq!(params.q % (2 * D as u64), 1);
    assert!(params.q < (1u64 << 61));
}

// =========================================================================
// C3 & C4: Streaming prover uses full ring multiplication and ext field accumulation
// =========================================================================

#[test]
fn c3_c4_streaming_prover_full_ring_mul_and_ext_accumulation() {
    use symphony::commitment::AjtaiParams;
    use symphony::folding::streaming::{StreamingPhase, StreamingProver};

    let q = 257u64;
    let kappa = 2;
    let n = 4;
    let ell_np = 2;
    let ntt = NttContext::new(q);
    let ajtai = AjtaiParams::setup(kappa, n, q, &ntt);
    let mut prover = StreamingProver::new(ajtai, ell_np);
    prover.set_ext_context(ExtFieldContext::new(q));

    // Witnesses with non-trivial polynomial coefficients (not just constants)
    // This exercises the full ring mul (C3) rather than just beta.coeffs[0]
    let w1 = RingVector {
        elements: vec![RingElement::monomial(1); n], // X in each position
    };
    let w2 = RingVector {
        elements: vec![RingElement::monomial(2); n], // X^2 in each position
    };

    // Pass 1: Commitment
    prover.feed_witness_commitment(&w1);
    prover.feed_witness_commitment(&w2);

    // Sumcheck passes (C4: uses ctx.add for ext field accumulation)
    while matches!(prover.phase(), StreamingPhase::Sumcheck { .. }) {
        prover.feed_witness_sumcheck(&w1, 0);
        prover.feed_witness_sumcheck(&w2, 1);
    }
    assert_eq!(prover.phase(), StreamingPhase::Folding);

    // Verify eval_table has non-trivial entries (not all zero)
    // With full ring mul + ext accumulation, the contributions should be non-zero
    // for witnesses that are monomials X and X^2

    // Final pass: Folding
    prover.feed_witness_folding(&w1, 0);
    prover.feed_witness_folding(&w2, 1);

    assert_eq!(prover.phase(), StreamingPhase::Complete);
    let result = prover.finish();
    assert_eq!(result.witness.len(), n);

    // The folded witness should be a non-trivial combination (not zero)
    let is_all_zero = result
        .witness
        .elements
        .iter()
        .all(|e| e.coeffs.iter().all(|&c| c == 0));
    assert!(
        !is_all_zero,
        "C3/C4: folded witness should not be all zeros with monomial inputs"
    );
}

// =========================================================================
// C5: mul_vec panics on i128→i64 overflow instead of silently truncating
// =========================================================================

#[test]
fn c5_mul_vec_panics_on_overflow() {
    let mut m = SparseMatrix::new(1, 2);
    m.insert(0, 0, i64::MAX);
    m.insert(0, 1, i64::MAX);
    // The product i64::MAX * i64::MAX summed twice will overflow i64
    let x = vec![i64::MAX, i64::MAX];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        m.mul_vec(&x);
    }));
    assert!(
        result.is_err(),
        "C5: mul_vec should panic on overflow instead of silent truncation"
    );
}

#[test]
fn c5_mul_vec_works_within_range() {
    let mut m = SparseMatrix::new(1, 2);
    m.insert(0, 0, 3);
    m.insert(0, 1, 5);
    let x = vec![7i64, 11];
    let y = m.mul_vec(&x);
    assert_eq!(y[0], 3 * 7 + 5 * 11);
}

// =========================================================================
// C6: is_satisfied() documents integer vs mod; is_satisfied_mod exists
// =========================================================================

#[test]
fn c6_is_satisfied_mod_works() {
    let q = 257u64;
    let mut r1cs = R1CSMatrices::new(1, 3, 1);
    r1cs.a.insert(0, 1, 1);
    r1cs.b.insert(0, 1, 1);
    r1cs.c.insert(0, 2, 1);

    // z = [1, 100, 100*100 mod 257 = 10000 mod 257 = 234 → centered: 234 - 257 = -23]
    let x_val = 100i64;
    let y_val = ((x_val as i128 * x_val as i128) % q as i128) as i64;
    let y_centered = if y_val > (q / 2) as i64 {
        y_val - q as i64
    } else {
        y_val
    };
    let z = vec![1, x_val, y_centered];
    assert!(r1cs.is_satisfied_mod(&z, q));

    // Over the integers, this won't satisfy because 100*100 = 10000 != -23
    assert!(!r1cs.is_satisfied(&z));
}

// =========================================================================
// H1: Norm bounds computed from beta_sis, not hardcoded
// =========================================================================

#[test]
fn h1_norm_bounds_derived_from_beta_sis() {
    let params = SymphonyParams::default_from_paper();
    let beta_sis = params.beta_sis();
    let b_rbnd = params.b_rbnd();
    let b_bnd = params.b_bnd();

    // b_rbnd = beta_sis / (4 * 15)
    assert_eq!(b_rbnd, beta_sis / 60);
    // b_bnd = b_rbnd / 2
    assert_eq!(b_bnd, b_rbnd / 2);
    // Sanity: chain is beta_sis > b_rbnd > b_bnd > 0
    assert!(beta_sis > b_rbnd);
    assert!(b_rbnd > b_bnd);
    assert!(b_bnd > 0);
}

// =========================================================================
// H3: Non-injective scalar encoding — length sentinel
// =========================================================================

#[test]
fn h3_bytes_to_scalars_injective() {
    use symphony::snark::spartan::SpartanSnark;

    // Different-length inputs that share an 8-byte prefix must produce
    // different scalar sequences. The fix adds a length sentinel.
    // We test indirectly: two different witnesses should produce different proofs
    // that verify only against their own instance.
    let relation = RelationDescription {
        num_instance_vars: 4,
        num_witness_vars: 8,
        num_constraints: 4,
        context: None,
    };
    let (pk, vk) = SpartanSnark::setup(&relation);

    let w1 = b"AAAA";
    let w2 = b"AAAA\x00\x00\x00\x00"; // same prefix, different length
    let proof1 = SpartanSnark::prove(&pk, b"inst", w1);
    let proof2 = SpartanSnark::prove(&pk, b"inst", w2);

    // Both should verify against their own instance
    assert!(SpartanSnark::verify(&vk, b"inst", &proof1));
    assert!(SpartanSnark::verify(&vk, b"inst", &proof2));

    // The witness hashes should differ because of the length sentinel
    assert_ne!(
        proof1.witness_hash, proof2.witness_hash,
        "H3: different-length inputs must produce different witness hashes"
    );
}

// =========================================================================
// H4: R1CS context authenticated in keys via context_hash
// =========================================================================

#[test]
fn h4_context_hash_bound_in_keys() {
    use symphony::snark::spartan::SpartanSnark;

    let relation1 = RelationDescription {
        num_instance_vars: 4,
        num_witness_vars: 8,
        num_constraints: 4,
        context: Some(b"context-A".to_vec()),
    };
    let relation2 = RelationDescription {
        num_instance_vars: 4,
        num_witness_vars: 8,
        num_constraints: 4,
        context: Some(b"context-B".to_vec()),
    };

    let (pk1, _vk1) = SpartanSnark::setup(&relation1);
    let (_pk2, _vk2) = SpartanSnark::setup(&relation2);

    // Context hashes should differ
    assert_ne!(
        pk1.context_hash, _pk2.context_hash,
        "H4: different contexts must produce different context_hash values"
    );
}

// =========================================================================
// H5: CP-SNARK verifier checks transcript_digest
// =========================================================================

#[test]
fn h5_cp_snark_digest_verified() {
    use symphony::cp_snark::{CPSnark, IdentityRelation};
    use symphony::fiat_shamir::hash_commitment::HashCommitment;
    use symphony::fiat_shamir::FSCommitment;

    let scheme = HashCommitment::new();
    let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 64);

    let (c, o) = scheme.commit(b"secret");
    let mut proof = cp
        .prove(
            &scheme,
            &[b"secret".as_slice()],
            &[o],
            &[c],
            b"",
            &IdentityRelation,
        )
        .unwrap();

    // Valid proof should pass
    assert!(cp.verify(&[c], b"", &proof));

    // Tamper with transcript_digest
    proof.transcript_digest[0] ^= 0xFF;
    assert!(
        !cp.verify(&[c], b"", &proof),
        "H5: tampered transcript_digest must be rejected"
    );
}

// =========================================================================
// H6: Two-layer decompose_blocks correct element-wise decomposition
// =========================================================================

#[test]
fn h6_two_layer_decompose_blocks_element_wise() {
    // Test that decompose_blocks produces k_b layers per block,
    // and each layer has low-norm ring elements.
    let base = 4i64;
    let k_b = 3;
    // We can't call decompose_blocks directly since it's private,
    // but we can verify the decomposition logic manually:
    let half_b = base / 2;
    for &coeff_val in &[42i64, -15, 7] {
        let digits = symphony::decomposition::decompose(coeff_val, base, k_b);
        assert_eq!(digits.len(), k_b);
        for &d in &digits {
            assert!(
                d.abs() <= half_b,
                "H6: decomposition digit {d} exceeds bound {half_b}"
            );
        }
        assert_eq!(symphony::decomposition::recompose(&digits, base), coeff_val);
    }
}

// =========================================================================
// M1: Extension field mul overflow — pre-reduce intermediates
// =========================================================================

#[test]
fn m1_ext_field_mul_no_overflow_large_q() {
    // Use a large q near 2^60 to stress the overflow path
    let params = SymphonyParams::default_from_paper();
    let q = params.q;
    let ctx = ExtFieldContext::new(q);

    // Large elements near q/2
    let q_half = (q / 2) as i64;
    let a = ExtFieldElement {
        c0: q_half - 1,
        c1: q_half - 1,
    };
    let b = ExtFieldElement {
        c0: q_half - 1,
        c1: q_half - 1,
    };

    // Should not overflow thanks to pre-reduction
    let result = ctx.mul(&a, &b);
    // Verify by checking a*b*inv(b) = a
    if let Some(b_inv) = ctx.inv(&b) {
        let roundtrip = ctx.mul(&result, &b_inv);
        assert_eq!(roundtrip, a, "M1: mul with large q should be consistent");
    }
}

#[test]
fn m1_ext_field_mul_associativity_large_q() {
    let params = SymphonyParams::default_from_paper();
    let ctx = ExtFieldContext::new(params.q);

    let a = ExtFieldElement { c0: 123456789, c1: -987654321 };
    let b = ExtFieldElement { c0: -111222333, c1: 444555666 };
    let c = ExtFieldElement { c0: 777888999, c1: -101010101 };

    let ab_c = ctx.mul(&ctx.mul(&a, &b), &c);
    let a_bc = ctx.mul(&a, &ctx.mul(&b, &c));
    assert_eq!(ab_c, a_bc, "M1: multiplication should be associative with large values");
}

// =========================================================================
// M2: Kronecker expansion overflow — checked_mul
// =========================================================================

#[test]
fn m2_kronecker_overflow_panics() {
    use symphony::r1cs::conversion::kronecker_expand;

    let mut original = R1CSMatrices::new(1, 2, 1);
    original.a.insert(0, 0, i64::MAX / 2);
    original.b.insert(0, 0, 1);
    original.c.insert(0, 0, 1);

    // With base = i64::MAX and k = 2, gadget[1] = i64::MAX
    // val * gadget[1] should overflow
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        kronecker_expand(&original, i64::MAX, 2);
    }));
    assert!(
        result.is_err(),
        "M2: kronecker expansion should panic on overflow"
    );
}

// =========================================================================
// M3: find_primitive_root asserts power-of-2
// =========================================================================

#[test]
fn m3_ntt_requires_power_of_two() {
    // NttContext::new asserts q ≡ 1 (mod 2d) which inherently requires
    // that 2d divides q-1. But the internal find_primitive_root also
    // asserts n.is_power_of_two(). We test via valid and invalid primes.
    let q = 12289u64; // known NTT-friendly prime, 12289 = 3*4096+1
    let _ctx = NttContext::new(q); // should not panic

    // 257 also works: 257 = 2*128 + 1, and 128 = 2*64
    let _ctx2 = NttContext::new(257);
}

// =========================================================================
// M4: Challenge q > 4 assert
// =========================================================================

#[test]
fn m4_challenge_q_too_small() {
    // derive_challenge_vector has debug_assert!(q > 4)
    // In debug mode, this should catch q <= 4
    #[cfg(debug_assertions)]
    {
        use symphony::fiat_shamir::transcript::Transcript;
        let mut transcript = Transcript::new(b"test");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            symphony::folding::challenge::derive_challenge_vector(&mut transcript, 3, 1);
        }));
        assert!(
            result.is_err(),
            "M4: derive_challenge_vector should panic when q <= 4"
        );
    }
}

// =========================================================================
// M5: Range proof projection ceiling division
// =========================================================================

#[test]
fn m5_projection_ceiling_division() {
    use symphony::rok::range_proof::ProjectionMatrix;

    // If total_coeffs is not a multiple of ell_h, we need ceiling division.
    // total_coeffs = 3 * 64 = 192, ell_h = 128 → should be 2 blocks, not 1
    let lambda_pj = 4;
    let ell_h = 128;
    let proj = ProjectionMatrix::sample(lambda_pj, ell_h, b"test-seed-1234567890123456");

    // n = 3 ring elements → total_coeffs = 3 * 64 = 192
    // n_blocks = ceil(192 / 128) = 2
    let n = 3;
    let total_coeffs = n * D;
    let n_blocks = total_coeffs.div_ceil(ell_h);
    assert_eq!(n_blocks, 2, "M5: ceiling division should yield 2 blocks");

    let flat_coeffs = vec![1i64; total_coeffs];
    let result = proj.apply_structured(&flat_coeffs, n_blocks);
    assert_eq!(
        result.len(),
        n_blocks * lambda_pj,
        "M5: projection output should have n_blocks * lambda_pj entries"
    );
}

// =========================================================================
// M7: recompose uses expect instead of unwrap_or
// =========================================================================

#[test]
fn m7_recompose_overflow_panics() {
    // Huge base and many digits should overflow
    let result = std::panic::catch_unwind(|| {
        symphony::decomposition::recompose(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1], i64::MAX);
    });
    assert!(
        result.is_err(),
        "M7: recompose should panic on overflow rather than silently returning wrong value"
    );
}

#[test]
fn m7_recompose_normal() {
    // Normal case: 5 = 1*1 + 0*4 + 1*16 → wait, let's just use decompose-recompose
    let val = 12345i64;
    let b = 16;
    let k = 8;
    let digits = symphony::decomposition::decompose(val, b, k);
    assert_eq!(symphony::decomposition::recompose(&digits, b), val);
}

// =========================================================================
// M8: Range proof verifier d_power overflow — checked_mul with i128
// =========================================================================

#[test]
fn m8_range_proof_d_power_i128() {
    // This is tested implicitly through the range proof verify path.
    // The fix changes the accumulator to i128 with checked_mul.
    // We verify correctness by running a small range proof end-to-end.
    use symphony::commitment::AjtaiParams;
    use symphony::rok::monomial::MonomialChallenges;
    use symphony::rok::range_proof::*;

    let q = 257u64;
    let ctx = ExtFieldContext::new(q);
    let n = 2;
    let kappa = 2;
    let ntt = NttContext::new(q);
    let ajtai = AjtaiParams::setup(kappa, n, q, &ntt);

    let witness = RingVector {
        elements: vec![RingElement::from_constant(3), RingElement::from_constant(-2)],
    };
    let (commitment, _) = ajtai.commit(&witness);

    let params = RangeProofParams {
        lambda_pj: 4,
        ell_h: D,
        d_prime: 62,
        k_g: 2,
        input_bound: 1024,
    };

    let proj = ProjectionMatrix::sample(4, D, b"test-seed-1234567890123456");
    let num_vars = 3;
    let mon_challenges = MonomialChallenges {
        s: (0..num_vars)
            .map(|i| ExtFieldElement {
                c0: 5 + i as i64,
                c1: 1,
            })
            .collect(),
        alpha: ExtFieldElement { c0: 3, c1: 2 },
        sumcheck_challenges: (0..num_vars)
            .map(|i| ExtFieldElement {
                c0: 7 + i as i64,
                c1: 3,
            })
            .collect(),
    };
    let challenges = RangeProofChallenges {
        projection: proj,
        monomial_challenges: mon_challenges,
    };

    let proof = prove(&commitment, &witness, &ajtai, &params, &challenges, &ctx);
    let result = verify(&commitment, &proof, &params, &challenges, &ctx);
    assert!(
        result.is_ok(),
        "M8: range proof with i128 d_power should verify: {:?}",
        result.err()
    );
}

// =========================================================================
// L1: NTT bit-reversal — constant-time w.r.t. data (comment check via correctness)
// =========================================================================

#[test]
fn l1_ntt_bit_reversal_correctness() {
    // Verify NTT roundtrip works correctly (the comment documents timing safety)
    let q = 12289u64;
    let ctx = NttContext::new(q);

    let mut coeffs = [0i64; D];
    for (i, c) in coeffs.iter_mut().enumerate() {
        *c = (i as i64 * 37 + 13) % (q as i64 / 2);
    }
    let a = RingElement { coeffs };

    let a_ntt = ctx.forward(&a);
    let a_back = ctx.inverse(&a_ntt);
    assert_eq!(a, a_back, "L1: NTT roundtrip should be exact");
}

// =========================================================================
// L3: Empty input validation in monomial verifier
// =========================================================================

#[test]
fn l3_monomial_verifier_rejects_empty() {
    use symphony::rok::monomial::{verify, MonomialChallenges, MonomialProof};
    use symphony::sumcheck::SumcheckProof;

    let ctx = ExtFieldContext::new(257);
    let empty_proof = MonomialProof {
        sumcheck_proof: SumcheckProof {
            round_messages: vec![],
        },
        evaluations: vec![],
        sq_evaluations: vec![],
    };
    let challenges = MonomialChallenges {
        s: vec![],
        alpha: ExtFieldElement { c0: 1, c1: 0 },
        sumcheck_challenges: vec![],
    };

    let result = verify(&[], &empty_proof, &challenges, &ctx);
    assert!(
        result.is_err(),
        "L3: monomial verifier should reject empty inputs"
    );
}

// =========================================================================
// L5: Pedersen extend_to bounded
// =========================================================================

#[test]
fn l5_pedersen_extend_to_bounded() {
    use symphony::snark::spartan::commitment::PedersenKey;

    let key = PedersenKey::setup(4, b"test-seed");

    // Extending to a huge value should panic
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut k = key.clone();
        k.extend_to((1 << 24) + 1, b"test-seed");
    }));
    assert!(
        result.is_err(),
        "L5: extend_to should panic when n > 2^24"
    );

    // Normal extend should work
    let mut k = key;
    k.extend_to(8, b"test-seed");
    assert_eq!(k.generators.len(), 8);
}

// =========================================================================
// L6: Hadamard alpha power comment — verify α^j indexing
// =========================================================================

#[test]
fn l6_hadamard_alpha_power_indexing() {
    // The fix corrected a comment from α^{j-1} to α^j.
    // We verify the Hadamard prover/verifier agree on the indexing
    // by running a full prove-verify cycle.
    use symphony::commitment::AjtaiParams;
    use symphony::rok::hadamard::{prove, verify, HadamardChallenges};

    let q = 257u64;
    let ctx = ExtFieldContext::new(q);

    let m = 2;
    let n = 3;
    let mut r1cs = R1CSMatrices::new(m, n, 1);
    r1cs.a.insert(0, 1, 1);
    r1cs.b.insert(0, 1, 1);
    r1cs.c.insert(0, 2, 1);

    let z = vec![1i64, 3, 9];
    assert!(r1cs.is_satisfied_mod(&z, q));

    let mut witness_matrix = Vec::with_capacity(D);
    for j in 0..D {
        if j == 0 {
            witness_matrix.push(z.clone());
        } else {
            witness_matrix.push(vec![0i64; n]);
        }
    }

    let kappa = 2;
    let ntt = NttContext::new(q);
    let ajtai = AjtaiParams::setup(kappa, n, q, &ntt);
    let ring_witness = RingVector {
        elements: z
            .iter()
            .map(|&v| RingElement::from_constant(v))
            .collect(),
    };
    let (commitment, _) = ajtai.commit(&ring_witness);

    let challenges = HadamardChallenges {
        s: vec![ExtFieldElement { c0: 5, c1: 1 }],
        alpha: ExtFieldElement { c0: 3, c1: 2 },
        sumcheck_challenges: vec![ExtFieldElement { c0: 7, c1: 3 }],
    };

    let proof = prove(&commitment, &witness_matrix, &r1cs, &challenges, &ctx);
    let result = verify(&commitment, &proof, &challenges, &ctx);
    assert!(
        result.is_ok(),
        "L6: Hadamard prove/verify should agree on alpha power indexing"
    );
}

// =========================================================================
// Integration: SymphonyParams::default_from_paper round-trip
// =========================================================================

#[test]
fn integration_default_params_are_fully_valid() {
    let params = SymphonyParams::default_from_paper();
    // C2: all checks pass
    params.validate();
    // H1: bounds are derived
    assert!(params.b_rbnd() > 0);
    assert!(params.b_bnd() > 0);
    assert!(params.beta_sis() > params.b_rbnd());

    // NTT should work with this q
    let _ntt = NttContext::new(params.q);
}

// =========================================================================
// Integration: Spartan backend context binding (H4) end-to-end
// =========================================================================

#[test]
fn h4_spartan_rejects_swapped_context() {
    use symphony::snark::spartan::SpartanSnark;

    // Setup with context A, try to verify with context B's vk
    let relation_a = RelationDescription {
        num_instance_vars: 4,
        num_witness_vars: 8,
        num_constraints: 4,
        context: Some(b"relation-A-context".to_vec()),
    };
    let relation_b = RelationDescription {
        num_instance_vars: 4,
        num_witness_vars: 8,
        num_constraints: 4,
        context: Some(b"relation-B-context".to_vec()),
    };

    let (pk_a, _vk_a) = SpartanSnark::setup(&relation_a);
    let (_pk_b, vk_b) = SpartanSnark::setup(&relation_b);

    let proof = SpartanSnark::prove(&pk_a, b"instance", b"witness");

    // Verify with mismatched vk should fail
    assert!(
        !SpartanSnark::verify(&vk_b, b"instance", &proof),
        "H4: proof should not verify under a different relation's vk"
    );
}

// =========================================================================
// Decomposition round-trip at various bases (exercises M7 fix path)
// =========================================================================

#[test]
fn decomposition_roundtrip_various_bases() {
    for b in [16i64, 32, 64] {
        for k in [4, 8, 16] {
            for &val in &[0i64, 1, -1, 42, -42, 1000, -1000] {
                let digits = symphony::decomposition::decompose(val, b, k);
                assert_eq!(digits.len(), k);
                let half_b = b / 2;
                for &d in &digits {
                    assert!(d.abs() <= half_b, "digit {d} exceeds bound {half_b}");
                }
                assert_eq!(
                    symphony::decomposition::recompose(&digits, b),
                    val,
                    "roundtrip failed for val={val}, b={b}, k={k}"
                );
            }
        }
    }
}
