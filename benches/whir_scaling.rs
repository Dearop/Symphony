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
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};
use symphony::commitment::Commitment;
use symphony::cp_snark::IdentityRelation;
use symphony::fiat_shamir::FSCommitment;
use symphony::folding::digest::Digest32;
use symphony::params::{SymphonyParams, D};
use symphony::proof_orchestrator::Prover;
use symphony::r1cs::R1CSMatrices;
use symphony::ring::{RingElement, RingVector};
use symphony::snark::whir::native_oracles::{
    native_round_message_view_eval_requests, profile_meets_native_non_zk_folding_integrity,
    prove_committed_private_manifest_membership, prove_native_manifest_source_membership,
    prove_native_round_message_oracle_views, symbt3_non_zk_folding_integrity_profile_report,
    verify_committed_private_manifest_membership, verify_native_manifest_source_membership,
    verify_native_round_message_oracle_views, ManifestCommitmentPolicy, NativeOracleRootPolicy,
    SourceCommitmentPolicy, Symbt3FoldingIntegritySemanticFamilies, Symbt3ManifestComponentKind,
    Symbt3ManifestSourceComponentValues, Symbt3ManifestVisibility, Symbt3MessageOraclePolicy,
    Symbt3NativeOracleProfile, Symbt3NativeRoundChallengeContext,
    Symbt3NativeRoundMessageOracleLayoutV1, Symbt3NonZkFoldingIntegrityProfileMetadata,
    Symbt3ZkStatus, SYMBT3_N4_MESSAGE_ORACLE_ID_BASE,
};
use symphony::snark::BackendSnark;
use symphony::snark::RelationDescription;
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

fn digest(label: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.finalize().into()
}

fn native_oracle_relation() -> RelationDescription {
    RelationDescription {
        num_instance_vars: 1,
        num_witness_vars: 1,
        num_constraints: 1,
        context: None,
    }
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
// 4. SYMBT3-N2 native manifest/source opening smoke counters
// ---------------------------------------------------------------------------

fn bench_symbt3_native_manifest_opening_vs_k(c: &mut Criterion) {
    let mut group = c.benchmark_group("whir_scaling/symbt3_native_manifest_opening_vs_k");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let (pk, vk) = WhirSnark::setup(&native_oracle_relation());

    for &k in &[1usize, 2, 4] {
        let len = 1usize << k;
        let manifest_evals = (0..len)
            .map(|i| BabyBear::from_u32(((i * 17 + k * 11 + 3) % 251) as u32))
            .collect::<Vec<_>>();
        let source_evals = manifest_evals.clone();
        let proof_relation_id = digest(format!("symbt3-n2-bench-relation-{k}").as_bytes());
        let public_statement_digest = digest(format!("symbt3-n2-bench-public-{k}").as_bytes());
        let whir_param_digest = digest(format!("symbt3-n2-bench-whir-{k}").as_bytes());
        let manifest_layout_digest =
            digest(format!("symbt3-n2-bench-manifest-layout-{k}").as_bytes());
        let source_layout_digest = digest(format!("symbt3-n2-bench-source-layout-{k}").as_bytes());

        let proof = prove_native_manifest_source_membership(
            &pk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            manifest_layout_digest,
            source_layout_digest,
            &manifest_evals,
            &source_evals,
        )
        .expect("SYMBT3-N2 native manifest/source proof must succeed");
        let report = verify_native_manifest_source_membership(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            manifest_layout_digest,
            source_layout_digest,
            proof.batch_manifest_root,
            ManifestCommitmentPolicy::NativeManifestOracleOpeningV1,
            SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &proof.native_proof.descriptors,
            &proof.native_proof,
        );
        assert!(
            report.ok,
            "SYMBT3-N2 native manifest/source proof failed for k={k}"
        );
        eprintln!(
            "[symbt3_native_manifest_opening_vs_k k={k}] \
             native_oracle_count={} native_oracle_descriptor_bytes={} \
             native_oracle_eval_claim_count={} native_oracle_opening_count={} \
             native_oracle_pcs_opening_count={} native_oracle_verify_ms={:.3} \
             family_columnar_subproof_count={} top_level_whir_proof_count={}",
            report.counters.native_oracle_count,
            report.counters.native_oracle_descriptor_bytes,
            report.counters.native_oracle_eval_claim_count,
            report.counters.native_oracle_opening_count,
            report.counters.native_oracle_pcs_opening_count,
            report.native_oracle_verify_ms,
            proof.native_proof.family_columnar_subproof_count(),
            proof.native_proof.top_level_whir_proof_count(),
        );

        group.throughput(Throughput::Elements(k as u64));

        group.bench_function(BenchmarkId::new("prove", k), |b| {
            b.iter(|| {
                black_box(
                    prove_native_manifest_source_membership(
                        black_box(&pk),
                        black_box(proof_relation_id),
                        black_box(public_statement_digest),
                        black_box(whir_param_digest),
                        black_box(manifest_layout_digest),
                        black_box(source_layout_digest),
                        black_box(&manifest_evals),
                        black_box(&source_evals),
                    )
                    .expect("SYMBT3-N2 native manifest/source proof must succeed"),
                );
            });
        });

        group.bench_function(BenchmarkId::new("verify", k), |b| {
            b.iter(|| {
                black_box(verify_native_manifest_source_membership(
                    black_box(&vk),
                    black_box(proof_relation_id),
                    black_box(public_statement_digest),
                    black_box(whir_param_digest),
                    black_box(manifest_layout_digest),
                    black_box(source_layout_digest),
                    black_box(proof.batch_manifest_root),
                    black_box(ManifestCommitmentPolicy::NativeManifestOracleOpeningV1),
                    black_box(SourceCommitmentPolicy::NativeSourceOracleOpeningV1),
                    black_box(NativeOracleRootPolicy::CanonicalWhirRootV1),
                    black_box(&proof.native_proof.descriptors),
                    black_box(&proof.native_proof),
                ));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 5. SYMBT3-N3 committed-private manifest/source smoke counters
// ---------------------------------------------------------------------------

fn symbt3_n3_bench_components(k: usize, len: usize) -> Vec<Symbt3ManifestSourceComponentValues> {
    let public_values = (0..len)
        .map(|i| BabyBear::from_u32(((i * 13 + k * 7 + 5) % 251) as u32))
        .collect::<Vec<_>>();
    let private_values = (0..len)
        .map(|i| BabyBear::from_u32(((i * 19 + k * 23 + 97) % 1_000_003) as u32))
        .collect::<Vec<_>>();

    vec![
        Symbt3ManifestSourceComponentValues {
            component_id: 1,
            kind: Symbt3ManifestComponentKind::PublicBoundary,
            visibility: Symbt3ManifestVisibility::PublicBoundary,
            layout_digest: digest(format!("symbt3-n3-bench-public-layout-{k}").as_bytes()),
            manifest_values: public_values.clone(),
            source_values: public_values,
        },
        Symbt3ManifestSourceComponentValues {
            component_id: 2,
            kind: Symbt3ManifestComponentKind::CommittedPrivateWitness,
            visibility: Symbt3ManifestVisibility::CommittedPrivateNonZk,
            layout_digest: digest(format!("symbt3-n3-bench-private-layout-{k}").as_bytes()),
            manifest_values: private_values.clone(),
            source_values: private_values,
        },
    ]
}

fn bench_symbt3_committed_private_manifest_vs_k(c: &mut Criterion) {
    let mut group = c.benchmark_group("whir_scaling/symbt3_committed_private_manifest_vs_k");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let (pk, vk) = WhirSnark::setup(&native_oracle_relation());

    for &k in &[1usize, 2, 4] {
        let len = 1usize << k;
        let components = symbt3_n3_bench_components(k, len);
        let proof_relation_id = digest(format!("symbt3-n3-bench-relation-{k}").as_bytes());
        let whir_param_digest = digest(format!("symbt3-n3-bench-whir-{k}").as_bytes());

        let proof = prove_committed_private_manifest_membership(
            &pk,
            proof_relation_id,
            whir_param_digest,
            Symbt3ZkStatus::NonZkIntegrityOnly,
            &components,
        )
        .expect("SYMBT3-N3 committed-private manifest proof must succeed");
        let report = verify_committed_private_manifest_membership(
            &vk,
            proof_relation_id,
            whir_param_digest,
            &proof,
        );
        assert!(
            report.ok,
            "SYMBT3-N3 committed-private manifest proof failed for k={k}"
        );
        eprintln!(
            "[symbt3_committed_private_manifest_vs_k k={k}] \
             native_oracle_count={} native_oracle_pcs_opening_count={} \
             committed_private_component_count={} committed_private_public_bytes={} \
             public_statement_bytes={} native_oracle_verify_ms={:.3} \
             top_level_whir_proof_count={} family_columnar_subproof_count={}",
            report.native_report.counters.native_oracle_count,
            report
                .native_report
                .counters
                .native_oracle_pcs_opening_count,
            report.committed_private_component_count,
            report.committed_private_public_bytes,
            report.public_statement_bytes,
            report.native_report.native_oracle_verify_ms,
            proof
                .membership_proof
                .native_proof
                .top_level_whir_proof_count(),
            proof
                .membership_proof
                .native_proof
                .family_columnar_subproof_count(),
        );

        group.throughput(Throughput::Elements(k as u64));

        group.bench_function(BenchmarkId::new("prove", k), |b| {
            b.iter(|| {
                black_box(
                    prove_committed_private_manifest_membership(
                        black_box(&pk),
                        black_box(proof_relation_id),
                        black_box(whir_param_digest),
                        black_box(Symbt3ZkStatus::NonZkIntegrityOnly),
                        black_box(&components),
                    )
                    .expect("SYMBT3-N3 committed-private manifest proof must succeed"),
                );
            });
        });

        group.bench_function(BenchmarkId::new("verify", k), |b| {
            b.iter(|| {
                black_box(verify_committed_private_manifest_membership(
                    black_box(&vk),
                    black_box(proof_relation_id),
                    black_box(whir_param_digest),
                    black_box(&proof),
                ));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 6. SYMBT3-N4/N4b native CP round-message oracle smoke counters
// ---------------------------------------------------------------------------

fn symbt3_n4_batch_log_size(batch_size: usize) -> usize {
    assert!(batch_size.is_power_of_two());
    batch_size.trailing_zeros() as usize
}

fn symbt3_n4_bench_context(
    round_count: usize,
    batch_size: usize,
) -> Symbt3NativeRoundChallengeContext {
    Symbt3NativeRoundChallengeContext {
        folding_protocol_id: digest(
            format!("symbt3-n4-bench-folding-{round_count}-{batch_size}").as_bytes(),
        ),
        input_public_boundary_digest: digest(
            format!("symbt3-n4-bench-input-{round_count}-{batch_size}").as_bytes(),
        ),
        batch_manifest_root: digest(
            format!("symbt3-n4-bench-manifest-root-{round_count}-{batch_size}").as_bytes(),
        ),
        source_roots_digest: digest(
            format!("symbt3-n4-bench-source-roots-{round_count}-{batch_size}").as_bytes(),
        ),
        active_count: batch_size as u64,
        batch_size: batch_size as u64,
        folded_output_digest: digest(
            format!("symbt3-n4-bench-folded-output-{round_count}-{batch_size}").as_bytes(),
        ),
    }
}

fn symbt3_n4_bench_layouts(
    round_count: usize,
    batch_log_size: usize,
) -> Vec<Symbt3NativeRoundMessageOracleLayoutV1> {
    (0..round_count)
        .map(|round| Symbt3NativeRoundMessageOracleLayoutV1 {
            round_index: round as u32,
            oracle_id: SYMBT3_N4_MESSAGE_ORACLE_ID_BASE + round as u32,
            batch_axis_log_size: batch_log_size,
            message_axis_log_size: 1,
            total_num_vars: batch_log_size + 1,
            layout_digest: digest(
                format!("symbt3-n4-bench-layout-{round_count}-{batch_log_size}-{round}").as_bytes(),
            ),
            section_layout_digest: digest(
                format!("symbt3-n4-bench-section-{round_count}-{batch_log_size}-{round}")
                    .as_bytes(),
            ),
            view_map_digest: digest(
                format!("symbt3-n4-bench-view-map-{round_count}-{batch_log_size}-{round}")
                    .as_bytes(),
            ),
        })
        .collect()
}

fn symbt3_n4_bench_evals(layouts: &[Symbt3NativeRoundMessageOracleLayoutV1]) -> Vec<Vec<BabyBear>> {
    layouts
        .iter()
        .map(|layout| {
            let len = 1usize << layout.total_num_vars;
            (0..len)
                .map(|i| {
                    BabyBear::from_u32(
                        ((layout.round_index as usize * 29 + i * 17 + 41) % 251) as u32,
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn bench_symbt3_native_message_oracles_vs_round_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("whir_scaling/symbt3_native_message_oracles_vs_round_count");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let (pk, vk) = WhirSnark::setup(&native_oracle_relation());

    let batch_size = 2usize;
    let batch_log_size = symbt3_n4_batch_log_size(batch_size);

    for &round_count in &[1usize, 2, 4] {
        let challenge_context = symbt3_n4_bench_context(round_count, batch_size);
        let round_layouts = symbt3_n4_bench_layouts(round_count, batch_log_size);
        let message_evals = symbt3_n4_bench_evals(&round_layouts);
        let eval_requests = native_round_message_view_eval_requests(&round_layouts);
        let proof_relation_id =
            digest(format!("symbt3-n4-bench-relation-rounds-{round_count}").as_bytes());
        let public_statement_digest =
            digest(format!("symbt3-n4-bench-public-rounds-{round_count}").as_bytes());
        let whir_param_digest =
            digest(format!("symbt3-n4-bench-whir-rounds-{round_count}").as_bytes());

        let proof = prove_native_round_message_oracle_views(
            &pk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &challenge_context,
            batch_log_size,
            &round_layouts,
            &message_evals,
            &eval_requests,
        )
        .expect("SYMBT3-N4 native message proof must succeed");
        let report = verify_native_round_message_oracle_views(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &challenge_context,
            batch_log_size,
            &round_layouts,
            proof.message_oracle_roots_digest,
            proof.message_round_layouts_digest,
            proof.message_oracle_policy_digest,
            Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &proof,
        );
        assert!(
            report.ok,
            "SYMBT3-N4 native message proof failed for round_count={round_count}"
        );
        eprintln!(
            "[symbt3_native_message_oracles_vs_round_count round_count={round_count}] \
             native_message_round_count={} native_oracle_count={} \
             native_oracle_eval_claim_count={} native_oracle_pcs_opening_count={} \
             native_oracle_descriptor_bytes={} native_oracle_verify_ms={:.3} \
             message_to_trace_binding_count={} family_columnar_subproof_count={} \
             top_level_whir_proof_count={}",
            report.native_message_round_count,
            report.native_report.counters.native_oracle_count,
            report.native_report.counters.native_oracle_eval_claim_count,
            report
                .native_report
                .counters
                .native_oracle_pcs_opening_count,
            report.native_report.counters.native_oracle_descriptor_bytes,
            report.native_report.native_oracle_verify_ms,
            report.message_to_trace_binding_count,
            proof.native_proof.family_columnar_subproof_count(),
            proof.native_proof.top_level_whir_proof_count(),
        );

        group.throughput(Throughput::Elements(round_count as u64));

        group.bench_function(BenchmarkId::new("prove", round_count), |b| {
            b.iter(|| {
                black_box(
                    prove_native_round_message_oracle_views(
                        black_box(&pk),
                        black_box(proof_relation_id),
                        black_box(public_statement_digest),
                        black_box(whir_param_digest),
                        black_box(&challenge_context),
                        black_box(batch_log_size),
                        black_box(&round_layouts),
                        black_box(&message_evals),
                        black_box(&eval_requests),
                    )
                    .expect("SYMBT3-N4 native message proof must succeed"),
                );
            });
        });

        group.bench_function(BenchmarkId::new("verify", round_count), |b| {
            b.iter(|| {
                black_box(verify_native_round_message_oracle_views(
                    black_box(&vk),
                    black_box(proof_relation_id),
                    black_box(public_statement_digest),
                    black_box(whir_param_digest),
                    black_box(&challenge_context),
                    black_box(batch_log_size),
                    black_box(&round_layouts),
                    black_box(proof.message_oracle_roots_digest),
                    black_box(proof.message_round_layouts_digest),
                    black_box(proof.message_oracle_policy_digest),
                    black_box(Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1),
                    black_box(NativeOracleRootPolicy::CanonicalWhirRootV1),
                    black_box(&proof),
                ));
            });
        });
    }

    group.finish();
}

fn bench_symbt3_native_message_oracles_batch_vs_k(c: &mut Criterion) {
    let mut group = c.benchmark_group("whir_scaling/symbt3_native_message_oracles_batch_vs_k");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let (pk, vk) = WhirSnark::setup(&native_oracle_relation());
    let round_count = 1usize;

    for &batch_size in &[1usize, 2, 4, 8] {
        let batch_log_size = symbt3_n4_batch_log_size(batch_size);
        let challenge_context = symbt3_n4_bench_context(round_count, batch_size);
        let round_layouts = symbt3_n4_bench_layouts(round_count, batch_log_size);
        let message_evals = symbt3_n4_bench_evals(&round_layouts);
        let eval_requests = native_round_message_view_eval_requests(&round_layouts);
        let proof_relation_id =
            digest(format!("symbt3-n4b-bench-relation-batch-{batch_size}").as_bytes());
        let public_statement_digest =
            digest(format!("symbt3-n4b-bench-public-batch-{batch_size}").as_bytes());
        let whir_param_digest =
            digest(format!("symbt3-n4b-bench-whir-batch-{batch_size}").as_bytes());

        let proof = prove_native_round_message_oracle_views(
            &pk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &challenge_context,
            batch_log_size,
            &round_layouts,
            &message_evals,
            &eval_requests,
        )
        .expect("SYMBT3-N4b native batch-axis message proof must succeed");
        let report = verify_native_round_message_oracle_views(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &challenge_context,
            batch_log_size,
            &round_layouts,
            proof.message_oracle_roots_digest,
            proof.message_round_layouts_digest,
            proof.message_oracle_policy_digest,
            Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &proof,
        );
        assert!(
            report.ok,
            "SYMBT3-N4b native batch-axis message proof failed for batch_size={batch_size}"
        );
        eprintln!(
            "[symbt3_native_message_oracles_batch_vs_k batch_size={batch_size}] \
             batch_size={} round_count={} native_oracle_count={} \
             native_oracle_pcs_opening_count={} native_oracle_eval_claim_count={} \
             native_message_round_count={} message_oracle_num_vars={} \
             native_oracle_verify_ms={:.3} family_columnar_subproof_count={} \
             top_level_whir_proof_count={}",
            batch_size,
            round_count,
            report.native_report.counters.native_oracle_count,
            report
                .native_report
                .counters
                .native_oracle_pcs_opening_count,
            report.native_report.counters.native_oracle_eval_claim_count,
            report.native_message_round_count,
            proof.native_proof.descriptors[0].num_vars,
            report.native_report.native_oracle_verify_ms,
            proof.native_proof.family_columnar_subproof_count(),
            proof.native_proof.top_level_whir_proof_count(),
        );

        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_function(BenchmarkId::new("prove", batch_size), |b| {
            b.iter(|| {
                black_box(
                    prove_native_round_message_oracle_views(
                        black_box(&pk),
                        black_box(proof_relation_id),
                        black_box(public_statement_digest),
                        black_box(whir_param_digest),
                        black_box(&challenge_context),
                        black_box(batch_log_size),
                        black_box(&round_layouts),
                        black_box(&message_evals),
                        black_box(&eval_requests),
                    )
                    .expect("SYMBT3-N4b native batch-axis message proof must succeed"),
                );
            });
        });

        group.bench_function(BenchmarkId::new("verify", batch_size), |b| {
            b.iter(|| {
                black_box(verify_native_round_message_oracle_views(
                    black_box(&vk),
                    black_box(proof_relation_id),
                    black_box(public_statement_digest),
                    black_box(whir_param_digest),
                    black_box(&challenge_context),
                    black_box(batch_log_size),
                    black_box(&round_layouts),
                    black_box(proof.message_oracle_roots_digest),
                    black_box(proof.message_round_layouts_digest),
                    black_box(proof.message_oracle_policy_digest),
                    black_box(Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1),
                    black_box(NativeOracleRootPolicy::CanonicalWhirRootV1),
                    black_box(&proof),
                ));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 7. SYMBT3-N5 native NonZK folding-integrity profile gate smoke counters
// ---------------------------------------------------------------------------

fn symbt3_n5_bench_metadata(
    batch_size: usize,
    round_count: usize,
) -> Symbt3NonZkFoldingIntegrityProfileMetadata {
    let batch_log_size = symbt3_n4_batch_log_size(batch_size);
    Symbt3NonZkFoldingIntegrityProfileMetadata {
        native_profile: Some(Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1),
        manifest_policy: Some(ManifestCommitmentPolicy::NativeManifestOracleOpeningV1),
        source_policy: Some(SourceCommitmentPolicy::NativeSourceOracleOpeningV1),
        message_oracle_policy: Some(Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1),
        root_policy: NativeOracleRootPolicy::CanonicalWhirRootV1,
        zk_status: Symbt3ZkStatus::NonZkIntegrityOnly,
        committed_private_component_count: 1,
        manifest_source_native_oracle_count: 2,
        manifest_source_native_pcs_opening_count: 2,
        native_message_round_count: round_count,
        native_message_oracle_count: round_count,
        native_message_pcs_opening_count: round_count,
        batch_size,
        batch_axis_log_size: batch_log_size,
        message_round_layouts: symbt3_n4_bench_layouts(round_count, batch_log_size),
        logical_native_envelope_count: 1,
        top_level_whir_proof_count: 1,
        family_columnar_subproof_count: 0,
        message_to_trace_binding_count: 0,
        semantic_profile_version: 5,
        required_semantic_families: Symbt3FoldingIntegritySemanticFamilies::production_non_zk(),
        k5_masking_available: false,
        monolithic_fallback: false,
        product_default_route_attempted: false,
        product_eligible: false,
        native_product_route_version_exists: false,
    }
}

fn bench_symbt3_native_folding_integrity_gate_vs_k(c: &mut Criterion) {
    let mut group = c.benchmark_group("whir_scaling/symbt3_native_folding_integrity_gate_vs_k");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(3));

    let round_count = 2usize;
    for &batch_size in &[1usize, 2, 4, 8] {
        let metadata = symbt3_n5_bench_metadata(batch_size, round_count);
        let report = symbt3_non_zk_folding_integrity_profile_report(&metadata);
        assert!(
            report.ok,
            "SYMBT3-N5 gate failed for batch_size={batch_size}"
        );
        eprintln!(
            "[symbt3_native_folding_integrity_gate_vs_k batch_size={batch_size}] \
             native_oracle_count_manifest_source={} native_oracle_count_messages={} \
             native_message_round_count={} native_message_oracle_count={} \
             native_message_oracle_count_is_round_count={} family_columnar_subproof_count={} \
             gate_ok={}",
            report.native_oracle_count_manifest_source,
            report.native_oracle_count_messages,
            report.native_message_round_count,
            report.native_message_oracle_count,
            report.native_message_oracle_count_is_round_count,
            report.family_columnar_subproof_count,
            report.gate_ok,
        );

        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_function(BenchmarkId::new("gate", batch_size), |b| {
            b.iter(|| {
                black_box(profile_meets_native_non_zk_folding_integrity(black_box(
                    &metadata,
                )));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_whir_cp_scaling,
    bench_pipeline_whir_vs_k,
    bench_modular_pipeline_whir_vs_k,
    bench_symbt3_native_manifest_opening_vs_k,
    bench_symbt3_committed_private_manifest_vs_k,
    bench_symbt3_native_message_oracles_vs_round_count,
    bench_symbt3_native_message_oracles_batch_vs_k,
    bench_symbt3_native_folding_integrity_gate_vs_k,
);
criterion_main!(benches);
