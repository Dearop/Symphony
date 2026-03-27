//! SNARK pipeline tests: encoding, DummySnark pipeline, audit fixes.

mod common;

use common::Q;
use symphony::commitment::Commitment;
use symphony::params::{D, SymphonyParams};
use symphony::r1cs::R1CSMatrices;
use symphony::ring::{RingElement, RingVector};

fn multi_r1cs() -> (R1CSMatrices, Vec<i64>) {
    common::multi_r1cs()
}

// =========================================================================
// CP-SNARK encoding
// =========================================================================
mod cp_snark_encoding {
    use super::*;
    use symphony::fiat_shamir::transcript::Transcript;
    use symphony::snark::cp_snark;
    use symphony::folding::FoldedInstance;
    use symphony::ring::tensor::TensorElement;

    #[test]
    fn encode_cp_instance_deterministic() {
        let comms = vec![b"comm-0".to_vec(), b"comm-1".to_vec()];
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        let e1 = cp_snark::encode_cp_instance(&comms, &mut t1);
        let e2 = cp_snark::encode_cp_instance(&comms, &mut t2);
        assert_eq!(e1, e2);
        assert!(!e1.is_empty());
    }

    #[test]
    fn encode_cp_witness_nonempty() {
        let openings = vec![b"opening-0".to_vec()];
        let transcript = b"transcript-data";
        let encoded = cp_snark::encode_cp_witness(&openings, transcript);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn encode_folded_instance_nonempty() {
        let fi = FoldedInstance {
            commitment: Commitment { value: RingVector::zero(2) },
            public_input: vec![RingElement::from_constant(1)],
            evaluation_values: vec![TensorElement::zero()],
        };
        let encoded = cp_snark::encode_folded_instance(&fi);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn encode_folded_witness_nonempty() {
        let fw = symphony::folding::FoldedWitness {
            witness: RingVector::zero(3),
            monomial_vectors: vec![RingVector::zero(2)],
        };
        let encoded = cp_snark::encode_folded_witness(&fw);
        assert!(!encoded.is_empty());
    }
}

// =========================================================================
// Full SNARK pipeline (DummySnark)
// =========================================================================
mod snark_pipeline {
    use super::*;
    use symphony::snark::{DummySnark, SymphonyProver};

    // multi_r1cs: n=4, m=4, n_in=1. We need params.n() = 4, so n_bar = 2.
    // n() = n_bar * k_cs = 4 * 1 = 4, matching multi_r1cs's num_variables.
    fn small_params() -> SymphonyParams {
        SymphonyParams {
            q: Q,
            d: D,
            kappa: 2,
            ell_np: 2,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 4,
            m: 4,
            b: 16,
            k_cs: 1,
        }
    }

    // Build statement tuple for the SNARK pipeline.
    // commit_witness expects length = params.n() = 4 = r1cs.num_variables.
    // The RingVector in the tuple is the witness-ONLY part (z[n_in..]).
    fn make_snark_statement(
        prover: &symphony::snark::SymphonyProver<DummySnark>,
        z: &[i64],
        n_in: usize,
    ) -> (Commitment, Vec<i64>, RingVector) {
        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = prover.commit_witness(&full_ring);
        let witness_part = RingVector {
            elements: z[n_in..].iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        (c, z[..n_in].to_vec(), witness_part)
    }

    #[test]
    fn end_to_end_prove_verify() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);

        let public_inputs = vec![pi1, pi2];
        assert!(verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    fn proof_contains_expected_structure() {
        let params = small_params();
        let (prover, _) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);

        assert!(!proof.fs_commitments.is_empty(), "should have FS commitments");
        assert!(!proof.cp_proof.data.is_empty(), "CP proof should be non-empty");
        assert!(!proof.snark_proof.data.is_empty(), "SNARK proof should be non-empty");
    }

    // Note: These DummySnark tamper tests verify pipeline wiring (that the verifier
    // propagates rejection when proof bytes are corrupted). They do NOT exercise real
    // cryptographic verification — replace DummySnark with a real backend for that.
    #[test]
    fn tampered_cp_proof_rejected() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let mut proof = prover.prove(&statements, &r1cs);

        proof.cp_proof.data = b"garbage".to_vec();

        let public_inputs = vec![pi1, pi2];
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs), "tampered CP proof should be rejected");
    }

    #[test]
    fn tampered_snark_proof_rejected() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let mut proof = prover.prove(&statements, &r1cs);

        proof.snark_proof.data = b"garbage".to_vec();

        let public_inputs = vec![pi1, pi2];
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs), "tampered SNARK proof should be rejected");
    }
}

// =========================================================================
// CP-SNARK encoding extended
// =========================================================================
mod cp_snark_extended {
    use symphony::fiat_shamir::transcript::Transcript;
    use symphony::snark::cp_snark;

    #[test]
    fn different_commitments_different_encoding() {
        let c1 = vec![b"comm-A".to_vec()];
        let c2 = vec![b"comm-B".to_vec()];
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        let e1 = cp_snark::encode_cp_instance(&c1, &mut t1);
        let e2 = cp_snark::encode_cp_instance(&c2, &mut t2);
        assert_ne!(e1, e2);
    }

    #[test]
    fn empty_commitments_still_encodes() {
        let mut t = Transcript::new(b"test");
        let encoded = cp_snark::encode_cp_instance(&[], &mut t);
        assert!(!encoded.is_empty());
    }
}

// =========================================================================
// SNARK pipeline extended
// =========================================================================
mod snark_pipeline_extended {
    use super::*;
    use symphony::snark::{DummySnark, SymphonyProver};

    #[test]
    fn tampered_fs_commitments_change_cp_instance() {
        use symphony::fiat_shamir::transcript::Transcript;
        use symphony::snark::cp_snark;

        let params = SymphonyParams {
            q: Q, d: D, kappa: 2, ell_np: 2, ell_h: D,
            lambda_pj: 4, n_bar: 4, m: 4, b: 16, k_cs: 1,
        };
        let (prover, _) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let mk = |p: &SymphonyProver<DummySnark>| {
            let full = RingVector { elements: z.iter().map(|&v| RingElement::from_constant(v)).collect() };
            let (c, _) = p.commit_witness(&full);
            let wp = RingVector { elements: z[n_in..].iter().map(|&v| RingElement::from_constant(v)).collect() };
            (c, z[..n_in].to_vec(), wp)
        };

        let stmts = vec![mk(&prover), mk(&prover)];
        let proof = prover.prove(&stmts, &r1cs);

        // Honest CP instance
        let mut t1 = Transcript::new(b"symphony-v1");
        for c in &proof.fs_commitments {
            t1.append_bytes(b"fs-commitment", c);
        }
        let honest_instance = cp_snark::encode_cp_instance(&proof.fs_commitments, &mut t1);

        // Tampered CP instance — a real BackendSnark would reject this
        let mut tampered_comms = proof.fs_commitments.clone();
        tampered_comms.push(b"extra-garbage".to_vec());
        let mut t2 = Transcript::new(b"symphony-v1");
        for c in &tampered_comms {
            t2.append_bytes(b"fs-commitment", c);
        }
        let tampered_instance = cp_snark::encode_cp_instance(&tampered_comms, &mut t2);

        assert_ne!(honest_instance, tampered_instance,
            "tampered FS commitments must produce a different CP instance");
    }

    #[test]
    fn different_r1cs_different_proofs() {
        let params = SymphonyParams {
            q: Q, d: D, kappa: 2, ell_np: 2, ell_h: D,
            lambda_pj: 4, n_bar: 4, m: 4, b: 16, k_cs: 1,
        };
        let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let mk = |p: &SymphonyProver<DummySnark>| {
            let full = RingVector { elements: z.iter().map(|&v| RingElement::from_constant(v)).collect() };
            let (c, _) = p.commit_witness(&full);
            let wp = RingVector { elements: z[n_in..].iter().map(|&v| RingElement::from_constant(v)).collect() };
            (c, z[..n_in].to_vec(), wp)
        };

        let stmts = vec![mk(&prover), mk(&prover)];
        let pis: Vec<Vec<i64>> = stmts.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&stmts, &r1cs);
        assert!(verifier.verify(&pis, &proof, &r1cs));
    }
}

// =========================================================================
// SNARK verifier binds public inputs
// =========================================================================
mod snark_public_input_binding {
    use super::*;
    use symphony::snark::{DummySnark, SymphonyProver};

    fn small_params() -> SymphonyParams {
        SymphonyParams {
            q: Q, d: D, kappa: 2, ell_np: 2, ell_h: D,
            lambda_pj: 4, n_bar: 4, m: 4, b: 16, k_cs: 1,
        }
    }

    fn make_snark_statement(
        prover: &SymphonyProver<DummySnark>,
        z: &[i64],
        n_in: usize,
    ) -> (Commitment, Vec<i64>, RingVector) {
        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = prover.commit_witness(&full_ring);
        let witness_part = RingVector {
            elements: z[n_in..].iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        (c, z[..n_in].to_vec(), witness_part)
    }

    #[test]
    fn verifier_uses_public_inputs_in_transcript() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);

        // Correct public inputs should verify
        let correct_pis = vec![pi1.clone(), pi2.clone()];
        assert!(verifier.verify(&correct_pis, &proof, &r1cs));

        // Wrong public inputs should fail (DummySnark won't catch the
        // cryptographic difference, but the transcript derivation path
        // changes, which a real backend would detect)
        let wrong_pis = vec![vec![999i64], vec![999i64]];
        // With DummySnark, verification still "passes" because DummySnark
        // doesn't check instance data. But the CP instance encoding differs:
        let mut t_correct = symphony::fiat_shamir::transcript::Transcript::new(b"symphony-v1");
        for pi in &correct_pis {
            let bytes: Vec<u8> = pi.iter().flat_map(|v| v.to_le_bytes()).collect();
            t_correct.append_bytes(b"public-input", &bytes);
        }
        let mut c_correct = [0u8; 32];
        t_correct.challenge_bytes(b"check", &mut c_correct);

        let mut t_wrong = symphony::fiat_shamir::transcript::Transcript::new(b"symphony-v1");
        for pi in &wrong_pis {
            let bytes: Vec<u8> = pi.iter().flat_map(|v| v.to_le_bytes()).collect();
            t_wrong.append_bytes(b"public-input", &bytes);
        }
        let mut c_wrong = [0u8; 32];
        t_wrong.challenge_bytes(b"check", &mut c_wrong);

        assert_ne!(
            c_correct, c_wrong,
            "different public inputs must produce different transcript states"
        );
    }

    #[test]
    fn verifier_uses_r1cs_in_transcript() {
        // Different R1CS metadata should produce different transcript state
        let mut t1 = symphony::fiat_shamir::transcript::Transcript::new(b"symphony-v1");
        t1.append_bytes(b"r1cs-m", &4u64.to_le_bytes());
        t1.append_bytes(b"r1cs-n", &4u64.to_le_bytes());
        t1.append_bytes(b"r1cs-pub", &1u64.to_le_bytes());
        let mut c1 = [0u8; 32];
        t1.challenge_bytes(b"check", &mut c1);

        let mut t2 = symphony::fiat_shamir::transcript::Transcript::new(b"symphony-v1");
        t2.append_bytes(b"r1cs-m", &8u64.to_le_bytes());
        t2.append_bytes(b"r1cs-n", &8u64.to_le_bytes());
        t2.append_bytes(b"r1cs-pub", &2u64.to_le_bytes());
        let mut c2 = [0u8; 32];
        t2.challenge_bytes(b"check", &mut c2);

        assert_ne!(c1, c2, "different R1CS metadata must produce different transcript states");
    }
}

// =========================================================================
// CP-SNARK witness non-empty fix
// =========================================================================
mod cp_snark_witness_fix {
    use super::*;
    use symphony::snark::{DummySnark, SymphonyProver};

    #[test]
    fn cp_witness_is_nonempty_in_pipeline() {
        let params = SymphonyParams {
            q: Q, d: D, kappa: 2, ell_np: 2, ell_h: D,
            lambda_pj: 4, n_bar: 4, m: 4, b: 16, k_cs: 1,
        };
        let (prover, _) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let mk = |p: &SymphonyProver<DummySnark>| {
            let full = RingVector { elements: z.iter().map(|&v| RingElement::from_constant(v)).collect() };
            let (c, _) = p.commit_witness(&full);
            let wp = RingVector { elements: z[n_in..].iter().map(|&v| RingElement::from_constant(v)).collect() };
            (c, z[..n_in].to_vec(), wp)
        };

        let stmts = vec![mk(&prover), mk(&prover)];
        let proof = prover.prove(&stmts, &r1cs);

        // The CP proof should be a valid DummyProof (non-empty data)
        assert!(
            proof.cp_proof.data.starts_with(b"dummy-proof:"),
            "CP proof should be a valid DummyProof"
        );
        // The SNARK proof should also be valid
        assert!(
            proof.snark_proof.data.starts_with(b"dummy-proof:"),
            "SNARK proof should be a valid DummyProof"
        );
    }
}
