//! Benchmarks comparing the linear (SumcheckSnark), classical-succinct (SpartanSnark),
//! and post-quantum-succinct (WhirSnark) CP paths.
//!
//! Run:  cargo bench --bench cp_succinct
//!       cargo bench --bench cp_succinct --features whir   # includes WHIR groups
//!
//! Groups (always present):
//!   cp_succinct/proof_size_scaling         – proof byte-size at various witness sizes
//!   cp_succinct/spartan_cp_scaling         – Spartan CP prove + verify time scaling
//!   cp_succinct/pipeline_spartan_vs_k      – full pipeline prove+verify with Spartan
//!
//! Groups (feature = "whir"):
//!   cp_succinct/whir_cp_scaling            – standalone CPSnark prove+verify (WHIR backend)
//!   cp_succinct/pipeline_whir_vs_k         – full pipeline prove+verify with WHIR

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use symphony::commitment::Commitment;
#[cfg(feature = "whir")]
use symphony::fiat_shamir::FSCommitment;
#[cfg(feature = "whir")]
use symphony::cp_snark::IdentityRelation;
use symphony::params::{SymphonyParams, D};
use symphony::r1cs::R1CSMatrices;
use symphony::ring::{RingElement, RingVector};
use symphony::snark::{BackendSnark, RelationDescription, SymphonyProver};
use symphony::{SpartanSnark, SumcheckSnark};
#[cfg(feature = "whir")]
use symphony::{CPSnark, HashCommitment, WhirSnark};

// ---------------------------------------------------------------------------
// Proof-size helpers
// ---------------------------------------------------------------------------

fn sumcheck_proof_wire_bytes(proof: &symphony::SumcheckProofData) -> usize {
    let mut size = 32usize;
    for round in &proof.sumcheck_proof.round_messages {
        size += round.evaluations.len() * 16;
    }
    size += 16;
    size += proof.witness_table.len() * 16;
    size += 8;
    size
}

fn spartan_proof_wire_bytes(proof: &symphony::SpartanProof) -> usize {
    let mut size = 32usize;
    for round in &proof.sumcheck_proof.round_polys {
        size += round.len() * 32;
    }
    size += 3 * 32;
    for ipa in &proof.ipa_proofs {
        size += ipa.lr_pairs.len() * 64;
        size += 32 + 32;
    }
    size += 32;
    size += 8;
    size
}

#[cfg(feature = "whir")]
fn whir_proof_wire_bytes(proof: &symphony::WhirProof) -> usize {
    let mut size = 0usize;
    // CP sumcheck rounds: 3 BabyBear per round = 12 bytes
    size += proof.sumcheck_rounds_3.len() * 12;
    // Output sumcheck rounds: 4 BabyBear per round = 16 bytes
    size += proof.sumcheck_rounds_4.len() * 16;
    // Evaluations: 3 BabyBear = 12 bytes
    size += 12;
    // z_eval: 4 bytes
    size += 4;
    // num_vars: 8 bytes
    size += 8;
    // is_output: 1 byte
    size += 1;
    // WHIR PCS proof: Merkle commitment + opening paths.
    // The initial_commitment is a Merkle root (32 bytes typically).
    // Each round has Merkle authentication paths. Approximate by counting rounds.
    let whir_rounds = proof.whir_pcs_proof.rounds.len();
    // ~32 bytes Merkle root + ~256 bytes per round (heuristic for Poseidon2 Merkle proofs)
    size += 32 + whir_rounds * 256;
    size
}

#[cfg(feature = "whir")]
fn cp_whir_proof_wire_bytes(proof: &symphony::CPProof<symphony::WhirSnark>) -> usize {
    // CP wrapper adds only a transcript digest on top of the backend proof.
    whir_proof_wire_bytes(&proof.backend_proof) + proof.transcript_digest.len()
}

// ---------------------------------------------------------------------------
// Common fixtures
// ---------------------------------------------------------------------------

fn bench_params(ell_np: usize) -> SymphonyParams {
    SymphonyParams {
        q: 257,
        d: D,
        kappa: 2,
        ell_np,
        ell_h: D,
        lambda_pj: 4,
        n_bar: 4,
        m: 4,
        b: 16,
        k_cs: 1,
        n_in: 1,
        ntt: SymphonyParams::try_ntt(257, D),
    }
}

fn make_snark_statement<S: BackendSnark>(
    prover: &SymphonyProver<S>,
    z: &[i64],
    n_in: usize,
) -> (Commitment, Vec<i64>, RingVector) {
    let full_ring = RingVector {
        elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
    };
    let (c, _) = prover.commit_witness(&full_ring);
    let witness_part = RingVector {
        elements: z[n_in..]
            .iter()
            .map(|&v| RingElement::from_constant(v))
            .collect(),
    };
    (c, z[..n_in].to_vec(), witness_part)
}

fn multi_r1cs() -> (R1CSMatrices, Vec<i64>) {
    let mut r1cs = R1CSMatrices::new(4, 4, 1);
    r1cs.a.insert(0, 1, 1);
    r1cs.b.insert(0, 2, 1);
    r1cs.c.insert(0, 3, 1);
    r1cs.a.insert(1, 1, 1);
    r1cs.b.insert(1, 0, 1);
    r1cs.c.insert(1, 1, 1);
    let z = vec![1i64, 3, 5, 15];
    (r1cs, z)
}

// ---------------------------------------------------------------------------
// 1. Proof size scaling: O(N) vs O(log N)
// ---------------------------------------------------------------------------

fn bench_proof_size_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("cp_succinct/proof_size_scaling");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(8));

    for &witness_size in &[256usize, 512, 1024, 2048, 4096, 8192] {
        let instance_size = (witness_size / 4).max(64);
        let relation = RelationDescription {
            num_instance_vars: instance_size,
            num_witness_vars: witness_size,
            num_constraints: (witness_size / 32).max(4),
            context: None,
        };

        let (sum_pk, sum_vk) = SumcheckSnark::setup(&relation);
        let (spa_pk, spa_vk) = SpartanSnark::setup(&relation);

        let instance: Vec<u8> = (0..instance_size)
            .map(|i| ((i * 17 + 13) % 251) as u8)
            .collect();
        let witness: Vec<u8> = (0..witness_size)
            .map(|i| ((i * 31 + 7) % 251) as u8)
            .collect();

        let sum_prove_start = Instant::now();
        let sum_proof = SumcheckSnark::prove(&sum_pk, &instance, &witness);
        let sum_prove_ms = sum_prove_start.elapsed().as_secs_f64() * 1_000.0;
        let sum_verify_start = Instant::now();
        let sum_ok = SumcheckSnark::verify(&sum_vk, &instance, &sum_proof);
        let sum_verify_ms = sum_verify_start.elapsed().as_secs_f64() * 1_000.0;
        assert!(sum_ok, "Sumcheck verify must pass for witness_size={witness_size}");

        let spa_prove_start = Instant::now();
        let spa_proof = SpartanSnark::prove(&spa_pk, &instance, &witness);
        let spa_prove_ms = spa_prove_start.elapsed().as_secs_f64() * 1_000.0;
        let spa_verify_start = Instant::now();
        let spa_ok = SpartanSnark::verify(&spa_vk, &instance, &spa_proof);
        let spa_verify_ms = spa_verify_start.elapsed().as_secs_f64() * 1_000.0;
        assert!(spa_ok, "Spartan verify must pass for witness_size={witness_size}");

        let sum_bytes = sumcheck_proof_wire_bytes(&sum_proof);
        let spa_bytes = spartan_proof_wire_bytes(&spa_proof);

        #[cfg(feature = "whir")]
        {
            use symphony::WhirSnark;
            let (whir_pk, whir_vk) = WhirSnark::setup(&relation);
            let whir_prove_start = Instant::now();
            let whir_proof = WhirSnark::prove(&whir_pk, &instance, &witness);
            let whir_prove_ms = whir_prove_start.elapsed().as_secs_f64() * 1_000.0;
            let whir_verify_start = Instant::now();
            let whir_ok = WhirSnark::verify(&whir_vk, &instance, &whir_proof);
            let whir_verify_ms = whir_verify_start.elapsed().as_secs_f64() * 1_000.0;
            assert!(whir_ok, "WHIR verify must pass for witness_size={witness_size}");

            let whir_bytes = whir_proof_wire_bytes(&whir_proof);
            eprintln!(
                "[proof_size] witness_size={witness_size} \
                 sumcheck={sum_bytes} spartan={spa_bytes} whir={whir_bytes} \
                 ratio_size_sumcheck_spartan={:.1}x ratio_size_sumcheck_whir={:.1}x \
                 ratio_prove_sumcheck_spartan={:.1}x ratio_prove_sumcheck_whir={:.1}x \
                 ratio_verify_sumcheck_spartan={:.1}x ratio_verify_sumcheck_whir={:.1}x",
                sum_bytes as f64 / spa_bytes as f64,
                sum_bytes as f64 / whir_bytes as f64,
                sum_prove_ms / spa_prove_ms.max(1e-9),
                sum_prove_ms / whir_prove_ms.max(1e-9),
                sum_verify_ms / spa_verify_ms.max(1e-9),
                sum_verify_ms / whir_verify_ms.max(1e-9),
            );

            group.bench_function(BenchmarkId::new("prove_whir", witness_size), |b| {
                b.iter(|| {
                    black_box(WhirSnark::prove(
                        black_box(&whir_pk),
                        black_box(&instance),
                        black_box(&witness),
                    ));
                });
            });

            group.bench_function(BenchmarkId::new("verify_whir", witness_size), |b| {
                b.iter(|| {
                    black_box(WhirSnark::verify(
                        black_box(&whir_vk),
                        black_box(&instance),
                        black_box(&whir_proof),
                    ));
                });
            });
        }
        #[cfg(not(feature = "whir"))]
        eprintln!(
            "[proof_size] witness_size={witness_size} \
             sumcheck={sum_bytes} spartan={spa_bytes} \
             ratio_size_sumcheck_spartan={:.1}x \
             ratio_prove_sumcheck_spartan={:.1}x \
             ratio_verify_sumcheck_spartan={:.1}x",
            sum_bytes as f64 / spa_bytes as f64,
            sum_prove_ms / spa_prove_ms.max(1e-9),
            sum_verify_ms / spa_verify_ms.max(1e-9),
        );

        group.throughput(Throughput::Elements(witness_size as u64));

        group.bench_function(BenchmarkId::new("prove_sumcheck", witness_size), |b| {
            b.iter(|| {
                black_box(SumcheckSnark::prove(
                    black_box(&sum_pk),
                    black_box(&instance),
                    black_box(&witness),
                ));
            });
        });

        group.bench_function(BenchmarkId::new("prove_spartan", witness_size), |b| {
            b.iter(|| {
                black_box(SpartanSnark::prove(
                    black_box(&spa_pk),
                    black_box(&instance),
                    black_box(&witness),
                ));
            });
        });

        group.bench_function(BenchmarkId::new("verify_sumcheck", witness_size), |b| {
            b.iter(|| {
                black_box(SumcheckSnark::verify(
                    black_box(&sum_vk),
                    black_box(&instance),
                    black_box(&sum_proof),
                ));
            });
        });

        group.bench_function(BenchmarkId::new("verify_spartan", witness_size), |b| {
            b.iter(|| {
                black_box(SpartanSnark::verify(
                    black_box(&spa_vk),
                    black_box(&instance),
                    black_box(&spa_proof),
                ));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 2. Spartan CP prove + verify scaling (classical, not PQ)
// ---------------------------------------------------------------------------

fn bench_spartan_cp_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("cp_succinct/spartan_cp_scaling");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &witness_size in &[256usize, 512, 1024, 2048, 4096, 8192] {
        let instance_size = (witness_size / 4).max(64);
        let relation = RelationDescription {
            num_instance_vars: instance_size,
            num_witness_vars: witness_size,
            num_constraints: (witness_size / 32).max(4),
            context: None,
        };

        let (pk, vk) = SpartanSnark::setup(&relation);

        let instance: Vec<u8> = (0..instance_size)
            .map(|i| ((i * 17 + 13) % 251) as u8)
            .collect();
        let witness: Vec<u8> = (0..witness_size)
            .map(|i| ((i * 31 + 7) % 251) as u8)
            .collect();

        let proof = SpartanSnark::prove(&pk, &instance, &witness);
        assert!(SpartanSnark::verify(&vk, &instance, &proof));

        let proof_bytes = spartan_proof_wire_bytes(&proof);
        eprintln!(
            "[spartan_cp] witness_size={witness_size} proof_bytes={proof_bytes} \
             num_vars={} ipa_rounds={}",
            proof.num_vars,
            proof.ipa_proofs[0].lr_pairs.len()
        );

        group.throughput(Throughput::Elements(witness_size as u64));

        group.bench_function(BenchmarkId::new("prove", witness_size), |b| {
            b.iter(|| {
                black_box(SpartanSnark::prove(
                    black_box(&pk),
                    black_box(&instance),
                    black_box(&witness),
                ));
            });
        });

        group.bench_function(BenchmarkId::new("verify", witness_size), |b| {
            b.iter(|| {
                black_box(SpartanSnark::verify(
                    black_box(&vk),
                    black_box(&instance),
                    black_box(&proof),
                ));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 3. Full pipeline with Spartan backend (classical)
// ---------------------------------------------------------------------------

fn bench_pipeline_spartan_vs_k(c: &mut Criterion) {
    let mut group = c.benchmark_group("cp_succinct/pipeline_spartan_vs_k");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    let (r1cs, z) = multi_r1cs();
    let n_in = r1cs.num_public;

    for &k in &[2usize, 4, 8] {
        let params = bench_params(k);
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);

        let statements: Vec<(Commitment, Vec<i64>, RingVector)> =
            (0..k).map(|_| make_snark_statement(&prover, &z, n_in)).collect();
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|(_, pi, _)| pi.clone()).collect();

        let proof = prover.prove(&statements, &r1cs);
        assert!(verifier.verify(&public_inputs, &proof, &r1cs));

        group.throughput(Throughput::Elements(k as u64));

        group.bench_function(BenchmarkId::new("prove", k), |b| {
            b.iter(|| {
                black_box(prover.prove(black_box(&statements), black_box(&r1cs)));
            });
        });

        group.bench_function(BenchmarkId::new("verify", k), |b| {
            b.iter(|| {
                black_box(verifier.verify(
                    black_box(&public_inputs),
                    black_box(&proof),
                    black_box(&r1cs),
                ));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 4. Standalone CP-SNARK (WHIR backend) prove + verify scaling (post-quantum)
// ---------------------------------------------------------------------------

#[cfg(feature = "whir")]
fn bench_whir_cp_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("cp_succinct/whir_cp_scaling");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &witness_size in &[256usize, 512, 1024, 2048, 4096] {
        let num_messages = 8usize;
        let max_message_size = (witness_size / num_messages).max(1);
        let cp = CPSnark::<WhirSnark, HashCommitment>::setup(num_messages, max_message_size);
        let scheme = HashCommitment::new();
        let relation = IdentityRelation;

        let messages: Vec<Vec<u8>> = (0..num_messages)
            .map(|msg_i| {
                (0..max_message_size)
                    .map(|byte_i| ((byte_i * 31 + msg_i * 17 + 7) % 251) as u8)
                    .collect()
            })
            .collect();
        let (commitments, openings): (Vec<_>, Vec<_>) =
            messages.iter().map(|msg| scheme.commit(msg)).unzip();
        let message_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();

        let proof = cp
            .prove(
                &scheme,
                &message_refs,
                &openings,
                &commitments,
                b"",
                &relation,
            )
            .expect("WHIR standalone CPSnark prove must succeed");
        assert!(
            cp.verify(&commitments, b"", &proof),
            "WHIR standalone CPSnark verify must pass for witness_size={witness_size}"
        );

        let proof_bytes = cp_whir_proof_wire_bytes(&proof);
        eprintln!(
            "[whir_cp_snark] witness_size={witness_size} proof_bytes~={proof_bytes} \
             num_vars={} whir_rounds={}",
            proof.backend_proof.num_vars,
            proof.backend_proof.whir_pcs_proof.rounds.len()
        );

        group.throughput(Throughput::Elements(witness_size as u64));

        group.bench_function(BenchmarkId::new("prove", witness_size), |b| {
            b.iter(|| {
                black_box(
                    cp.prove(
                        black_box(&scheme),
                        black_box(&message_refs),
                        black_box(&openings),
                        black_box(&commitments),
                        black_box(b""),
                        black_box(&relation),
                    )
                    .expect("WHIR standalone CPSnark prove must succeed"),
                );
            });
        });

        group.bench_function(BenchmarkId::new("verify", witness_size), |b| {
            b.iter(|| {
                black_box(cp.verify(
                    black_box(&commitments),
                    black_box(b""),
                    black_box(&proof),
                ));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 5. Full pipeline with WHIR backend (post-quantum)
// ---------------------------------------------------------------------------

#[cfg(feature = "whir")]
fn bench_pipeline_whir_vs_k(c: &mut Criterion) {
    use symphony::WhirSnark;

    let mut group = c.benchmark_group("cp_succinct/pipeline_whir_vs_k");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    let (r1cs, z) = multi_r1cs();
    let n_in = r1cs.num_public;

    for &k in &[2usize, 4] {
        let params = bench_params(k);
        let (prover, verifier) = SymphonyProver::<WhirSnark>::setup(params);

        let statements: Vec<(Commitment, Vec<i64>, RingVector)> =
            (0..k).map(|_| make_snark_statement(&prover, &z, n_in)).collect();
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|(_, pi, _)| pi.clone()).collect();

        let proof = prover.prove(&statements, &r1cs);
        assert!(
            verifier.verify(&public_inputs, &proof, &r1cs),
            "WHIR pipeline verify must pass for k={k}"
        );

        group.throughput(Throughput::Elements(k as u64));

        group.bench_function(BenchmarkId::new("prove", k), |b| {
            b.iter(|| {
                black_box(prover.prove(black_box(&statements), black_box(&r1cs)));
            });
        });

        group.bench_function(BenchmarkId::new("verify", k), |b| {
            b.iter(|| {
                black_box(verifier.verify(
                    black_box(&public_inputs),
                    black_box(&proof),
                    black_box(&r1cs),
                ));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------

#[cfg(not(feature = "whir"))]
criterion_group!(
    benches,
    bench_proof_size_scaling,
    bench_spartan_cp_scaling,
    bench_pipeline_spartan_vs_k,
);

#[cfg(feature = "whir")]
criterion_group!(
    benches,
    bench_proof_size_scaling,
    bench_spartan_cp_scaling,
    bench_pipeline_spartan_vs_k,
    bench_whir_cp_scaling,
    bench_pipeline_whir_vs_k,
);

criterion_main!(benches);
