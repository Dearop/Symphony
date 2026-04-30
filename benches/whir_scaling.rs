//! WHIR-only scaling benchmarks.
//!
//! Run:
//!   cargo bench --bench whir_scaling --features whir
//!   cargo bench --bench whir_scaling --features whir -- "whir_cp_scaling"
//!   cargo bench --bench whir_scaling --features whir -- "pipeline_whir_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "modular_pipeline_whir_vs_k"
//!
//! Groups:
//!   whir_scaling/whir_cp_scaling            – standalone CPSnark prove+verify (WHIR backend)
//!   whir_scaling/pipeline_whir_vs_k         – full pipeline prove+verify with WHIR vs k
//!   whir_scaling/modular_pipeline_whir_vs_k – split CP/output WHIR backends vs k

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use symphony::commitment::Commitment;
use symphony::cp_snark::IdentityRelation;
use symphony::fiat_shamir::FSCommitment;
use symphony::params::{SymphonyParams, D};
use symphony::proof_orchestrator::Prover;
use symphony::r1cs::R1CSMatrices;
use symphony::ring::{RingElement, RingVector};
use symphony::snark::BackendSnark;
use symphony::{CPSnark, HashCommitment, SumcheckSnark, WhirSnark};

// ---------------------------------------------------------------------------
// Fixtures
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

fn make_snark_statement<S: BackendSnark>(
    prover: &Prover<S, S>,
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

fn make_modular_statement<
    CPB: symphony::cp_backend_api::CpBackend,
    OB: symphony::output_backend_api::OutputBackend,
>(
    prover: &Prover<CPB, OB>,
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

fn whir_proof_wire_bytes(proof: &symphony::WhirProof) -> usize {
    let mut size = 0usize;
    size += proof.sumcheck_rounds_3.len() * 12;
    size += proof.sumcheck_rounds_4.len() * 16;
    size += 12 + 4 + 8 + 1;
    let whir_rounds = proof.whir_pcs_proof.rounds.len();
    size += 32 + whir_rounds * 256;
    size
}

// ---------------------------------------------------------------------------
// 1. Standalone CPSnark with WHIR backend: prove + verify vs witness size
// ---------------------------------------------------------------------------

fn bench_whir_cp_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("whir_scaling/whir_cp_scaling");
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
            .expect("WHIR CPSnark prove must succeed");
        assert!(
            cp.verify(&scheme, &commitments, b"", &relation, &proof),
            "WHIR CPSnark verify must pass for witness_size={witness_size}"
        );

        let proof_bytes =
            whir_proof_wire_bytes(&proof.backend_proof) + proof.transcript_digest.len();
        eprintln!(
            "[whir_cp_scaling] witness_size={witness_size} proof_bytes~={proof_bytes} \
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
                    .expect("WHIR CPSnark prove must succeed"),
                );
            });
        });

        group.bench_function(BenchmarkId::new("verify", witness_size), |b| {
            b.iter(|| {
                black_box(cp.verify(
                    black_box(&scheme),
                    black_box(&commitments),
                    black_box(b""),
                    black_box(&relation),
                    black_box(&proof),
                ));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 2. Full pipeline with homogeneous WHIR backend: prove + verify vs k
// ---------------------------------------------------------------------------

fn bench_pipeline_whir_vs_k(c: &mut Criterion) {
    let mut group = c.benchmark_group("whir_scaling/pipeline_whir_vs_k");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    let (r1cs, z) = multi_r1cs();
    let n_in = r1cs.num_public;

    for &k in &[2usize, 4] {
        let params = bench_params(k);
        let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(params);

        let statements: Vec<(Commitment, Vec<i64>, RingVector)> = (0..k)
            .map(|_| make_snark_statement(&prover, &z, n_in))
            .collect();
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|(_, pi, _)| pi.clone()).collect();

        let proof = prover.prove(&statements, &r1cs);
        let verify_ok = verifier.verify(&public_inputs, &proof, &r1cs);
        eprintln!("[pipeline_whir_vs_k k={k}] verify={verify_ok}");
        assert!(
            verify_ok,
            "pipeline_whir_vs_k produced invalid proof for k={k}"
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
// 3. Modular pipeline with WHIR backend variants vs k
// ---------------------------------------------------------------------------

fn bench_modular_pipeline_whir_vs_k(c: &mut Criterion) {
    let mut group = c.benchmark_group("whir_scaling/modular_pipeline_whir_vs_k");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    let (r1cs, z) = multi_r1cs();
    let n_in = r1cs.num_public;

    for &k in &[2usize, 4] {
        let params = bench_params(k);

        // WHIR CP + WHIR Output (homogeneous PQ)
        {
            let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(params.clone());
            let statements: Vec<_> = (0..k)
                .map(|_| make_modular_statement(&prover, &z, n_in))
                .collect();
            let public_inputs: Vec<Vec<i64>> =
                statements.iter().map(|(_, pi, _)| pi.clone()).collect();
            let proof = prover.prove(&statements, &r1cs);
            let verify_ok = verifier.verify(&public_inputs, &proof, &r1cs);
            eprintln!("[modular_pipeline k={k}] whir+whir verify={verify_ok}");
            assert!(
                verify_ok,
                "modular_pipeline whir+whir produced invalid proof for k={k}"
            );

            group.throughput(Throughput::Elements(k as u64));

            group.bench_function(BenchmarkId::new("prove_whir_whir", k), |b| {
                b.iter(|| {
                    black_box(prover.prove(black_box(&statements), black_box(&r1cs)));
                });
            });
            group.bench_function(BenchmarkId::new("verify_whir_whir", k), |b| {
                b.iter(|| {
                    black_box(verifier.verify(
                        black_box(&public_inputs),
                        black_box(&proof),
                        black_box(&r1cs),
                    ));
                });
            });
        }

        // WHIR CP + Sumcheck Output (hybrid)
        {
            let (prover, verifier) = Prover::<WhirSnark, SumcheckSnark>::setup(params.clone());
            let statements: Vec<_> = (0..k)
                .map(|_| make_modular_statement(&prover, &z, n_in))
                .collect();
            let public_inputs: Vec<Vec<i64>> =
                statements.iter().map(|(_, pi, _)| pi.clone()).collect();
            let proof = prover.prove(&statements, &r1cs);
            let verify_ok = verifier.verify(&public_inputs, &proof, &r1cs);
            eprintln!("[modular_pipeline k={k}] whir+sum verify={verify_ok}");
            assert!(
                verify_ok,
                "modular_pipeline whir+sum produced invalid proof for k={k}"
            );

            group.bench_function(BenchmarkId::new("prove_whir_sum", k), |b| {
                b.iter(|| {
                    black_box(prover.prove(black_box(&statements), black_box(&r1cs)));
                });
            });
            group.bench_function(BenchmarkId::new("verify_whir_sum", k), |b| {
                b.iter(|| {
                    black_box(verifier.verify(
                        black_box(&public_inputs),
                        black_box(&proof),
                        black_box(&r1cs),
                    ));
                });
            });
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_whir_cp_scaling,
    bench_pipeline_whir_vs_k,
    bench_modular_pipeline_whir_vs_k,
);
criterion_main!(benches);
