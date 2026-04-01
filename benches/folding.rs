//! Benchmarks focused on architecture-level scaling.
//!
//! In addition to Criterion timing groups, this file records a scaling report at:
//! `target/criterion/scaling/sumcheck_scaling.csv`
//! with per-stage elapsed time, peak heap usage, and pass-count diagnostics.

use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::{self, OpenOptions};
use std::hint::black_box;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use symphony::commitment::{AjtaiParams, Commitment};
use symphony::fiat_shamir::hash_commitment::HashCommitment;
use symphony::fiat_shamir::transcript::Transcript;
use symphony::fiat_shamir::FSCommitment;
use symphony::folding::digest::{
    digest_challenges, digest_fold_inputs, digest_fs_commitments, digest_transcript_seed, Digest32,
    FoldInput,
};
use symphony::folding::streaming::{StreamingPhase, StreamingProver};
use symphony::folding::{FoldedInstance, FoldingStatement};
use symphony::params::{SymphonyParams, D};
use symphony::r1cs::R1CSMatrices;
use symphony::ring::extension::{ExtFieldContext, ExtFieldElement};
use symphony::ring::ntt::NttContext;
use symphony::ring::{RingElement, RingVector};
use symphony::rok::range_proof::RangeProofParams;
use symphony::snark::cp_snark as pipeline_cp_snark;
use symphony::snark::{
    BackendSnark, DummySnark, RelationDescription, SymphonyProver, SymphonyVerifier,
};
use symphony::sumcheck::prover;
use symphony::sumcheck::{self, SumcheckClaim};
use symphony::{SpartanProof, SpartanSnark, SumcheckSnark};
#[cfg(feature = "whir")]
use symphony::{WhirProof, WhirSnark};

const SCALING_KS: &[usize] = &[2, 4, 8, 16, 32];
const SCALING_REPORT_PATH: &str = "target/criterion/scaling/sumcheck_scaling.csv";

// -----------------------------------------------------------------------------
// Lightweight heap tracker (used only for one-shot diagnostics).
// -----------------------------------------------------------------------------

struct TrackingAllocator;

static TRACK_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static CURRENT_HEAP_BYTES: AtomicU64 = AtomicU64::new(0);
static PEAK_HEAP_BYTES: AtomicU64 = AtomicU64::new(0);
static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

fn update_peak(current: u64) {
    let mut peak = PEAK_HEAP_BYTES.load(Ordering::Relaxed);
    while current > peak {
        match PEAK_HEAP_BYTES.compare_exchange_weak(
            peak,
            current,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => peak = observed,
        }
    }
}

fn track_alloc(size: usize) {
    let new_current = CURRENT_HEAP_BYTES.fetch_add(size as u64, Ordering::Relaxed) + size as u64;
    ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    ALLOCATED_BYTES.fetch_add(size as u64, Ordering::Relaxed);
    update_peak(new_current);
}

fn track_dealloc(size: usize) {
    let _ = CURRENT_HEAP_BYTES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
        Some(cur.saturating_sub(size as u64))
    });
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if TRACK_ALLOCATIONS.load(Ordering::Relaxed) && !ptr.is_null() {
            track_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if TRACK_ALLOCATIONS.load(Ordering::Relaxed) {
            track_dealloc(layout.size());
        }
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if TRACK_ALLOCATIONS.load(Ordering::Relaxed) && !new_ptr.is_null() {
            if new_size >= layout.size() {
                track_alloc(new_size - layout.size());
            } else {
                track_dealloc(layout.size() - new_size);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: TrackingAllocator = TrackingAllocator;

#[derive(Debug, Clone, Copy)]
struct ResourceStats {
    elapsed: Duration,
    peak_heap_bytes: u64,
    alloc_calls: usize,
    allocated_bytes: u64,
}

fn measure_resources<T>(f: impl FnOnce() -> T) -> (T, ResourceStats) {
    CURRENT_HEAP_BYTES.store(0, Ordering::Relaxed);
    PEAK_HEAP_BYTES.store(0, Ordering::Relaxed);
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);

    TRACK_ALLOCATIONS.store(true, Ordering::SeqCst);
    let start = Instant::now();
    let out = f();
    let elapsed = start.elapsed();
    TRACK_ALLOCATIONS.store(false, Ordering::SeqCst);

    (
        out,
        ResourceStats {
            elapsed,
            peak_heap_bytes: PEAK_HEAP_BYTES.load(Ordering::Relaxed),
            alloc_calls: ALLOC_CALLS.load(Ordering::Relaxed),
            allocated_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
        },
    )
}

static REPORT_INIT: Once = Once::new();

fn init_scaling_report() {
    REPORT_INIT.call_once(|| {
        let report_dir = "target/criterion/scaling";
        fs::create_dir_all(report_dir).expect("must create scaling report directory");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(SCALING_REPORT_PATH)
            .expect("must create scaling report file");

        writeln!(
            file,
            "stage,k,elapsed_ms,peak_heap_bytes,alloc_calls,allocated_bytes,pass_count,notes"
        )
        .expect("must write scaling report header");
    });
}

fn record_scaling_row(
    stage: &str,
    k: usize,
    stats: &ResourceStats,
    pass_count: usize,
    notes: &str,
) {
    init_scaling_report();

    let mut file = OpenOptions::new()
        .append(true)
        .open(SCALING_REPORT_PATH)
        .expect("must append scaling report");

    let elapsed_ms = stats.elapsed.as_secs_f64() * 1_000.0;

    writeln!(
        file,
        "{stage},{k},{elapsed_ms:.3},{},{},{},{},{}",
        stats.peak_heap_bytes, stats.alloc_calls, stats.allocated_bytes, pass_count, notes
    )
    .expect("must write scaling row");

    eprintln!(
        "[scaling] stage={stage} k={k} elapsed_ms={elapsed_ms:.3} peak_heap={} pass_count={} report={SCALING_REPORT_PATH}",
        stats.peak_heap_bytes,
        pass_count,
    );
}

// -----------------------------------------------------------------------------
// Common fixtures
// -----------------------------------------------------------------------------

fn multi_r1cs() -> (R1CSMatrices, Vec<i64>) {
    let m = 4;
    let n = 4;
    let mut r1cs = R1CSMatrices::new(m, n, 1);
    r1cs.a.insert(0, 1, 1);
    r1cs.b.insert(0, 2, 1);
    r1cs.c.insert(0, 3, 1);
    r1cs.a.insert(1, 1, 1);
    r1cs.b.insert(1, 0, 1);
    r1cs.c.insert(1, 1, 1);
    let z = vec![1i64, 3, 5, 15];
    (r1cs, z)
}

fn range_params() -> RangeProofParams {
    RangeProofParams {
        lambda_pj: 4,
        ell_h: D,
        d_prime: 62,
        k_g: 2,
        input_bound: 1024,
    }
}

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

fn make_folding_statement(z: &[i64], n_in: usize, ajtai: &AjtaiParams) -> FoldingStatement {
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

fn folding_pass_count_model() -> usize {
    // Current non-streaming folding path performs 6 full passes over statements.
    6
}

fn pipeline_prove_pass_count_model() -> usize {
    // SNARK prove currently does 3 statement passes before/after folding,
    // and folding itself contributes 6 statement passes.
    9
}

fn pipeline_verify_pass_count_model() -> usize {
    // Verify scans public inputs once and FS commitments once.
    2
}

fn cp_pipeline_prove_pass_count_model() -> usize {
    // CP stage prove: 2 passes over fs commitments for instance encoding + 1 for witness encoding.
    3
}

fn cp_pipeline_verify_pass_count_model() -> usize {
    // CP stage verify: transcript bind + instance encoding over fs commitments.
    2
}

fn log2_ceil(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        (usize::BITS - (n - 1).leading_zeros()) as usize
    }
}

fn streaming_sumcheck_passes(n: usize) -> usize {
    let log_n = log2_ceil(n.max(2));
    let log_log_n = log2_ceil(log_n.max(2));
    2 + log_log_n.max(1)
}

fn streaming_total_passes(n: usize) -> usize {
    // commitment pass + sumcheck passes + final folding pass
    1 + streaming_sumcheck_passes(n) + 1
}

struct PipelineFixture<S: BackendSnark> {
    prover: SymphonyProver<S>,
    verifier: SymphonyVerifier<S>,
    r1cs: R1CSMatrices,
    statements: Vec<(Commitment, Vec<i64>, RingVector)>,
    public_inputs: Vec<Vec<i64>>,
}

fn build_pipeline_fixture<S: BackendSnark>(k: usize) -> PipelineFixture<S> {
    let params = bench_params(k);
    let (prover, verifier) = SymphonyProver::<S>::setup(params);

    let (r1cs, z) = multi_r1cs();
    let n_in = r1cs.num_public;

    let statements: Vec<(Commitment, Vec<i64>, RingVector)> = (0..k)
        .map(|_| make_snark_statement(&prover, &z, n_in))
        .collect();

    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|(_, pi, _)| pi.clone()).collect();

    PipelineFixture {
        prover,
        verifier,
        r1cs,
        statements,
        public_inputs,
    }
}

fn build_pipeline_fixture_sumcheck(k: usize) -> PipelineFixture<SumcheckSnark> {
    build_pipeline_fixture::<SumcheckSnark>(k)
}

#[derive(Clone)]
struct CpPipelineMaterial {
    fs_commitments: Vec<Vec<u8>>,
    fs_openings: Vec<Vec<u8>>,
    fs_messages: Vec<Vec<u8>>,
    folding_transcript_witness: Vec<u8>,
    fold_inputs: Vec<FoldInput>,
    fold_root: Digest32,
    fs_root: Digest32,
    transcript_seed_digest: Digest32,
    folded_instance: FoldedInstance,
    public_inputs: Vec<Vec<i64>>,
    r1cs_num_constraints: usize,
    r1cs_num_variables: usize,
    r1cs_num_public: usize,
}

fn build_cp_pipeline_material<S: BackendSnark>(fixture: &PipelineFixture<S>) -> CpPipelineMaterial {
    let folding_statements: Vec<FoldingStatement> = fixture
        .statements
        .iter()
        .map(|(c, pi, w)| FoldingStatement {
            commitment: c.clone(),
            public_input: pi.clone(),
            witness: w.clone(),
        })
        .collect();

    let rp = range_params();
    let ext_ctx = ExtFieldContext::new(fixture.prover.params.q);
    let (folding_proof, _, _) = symphony::folding::prove(
        &folding_statements,
        &fixture.r1cs,
        &fixture.prover.ajtai,
        &rp,
        &ext_ctx,
    );

    let fs_messages: Vec<Vec<u8>> = folding_proof
        .gr1cs_proofs
        .iter()
        .map(pipeline_cp_snark::encode_gr1cs_round_message)
        .collect();
    let fs_scheme = HashCommitment::new();
    let mut fs_commitments = Vec::with_capacity(fs_messages.len());
    let mut fs_openings = Vec::with_capacity(fs_messages.len());
    for message in &fs_messages {
        let (commitment, opening) = fs_scheme.commit(message);
        fs_commitments.push(commitment.to_vec());
        fs_openings.push(opening.to_vec());
    }

    let folding_transcript_witness =
        pipeline_cp_snark::encode_folding_transcript_witness(&folding_proof, &fs_messages);

    // Mirror prover logic for compressed CP witness: include fold inputs and fold_root.
    let fold_inputs: Vec<FoldInput> = fixture
        .statements
        .iter()
        .enumerate()
        .map(|(i, (c, pi, _))| FoldInput {
            commitment_bytes: pipeline_cp_snark::encode_commitment_to_bytes(c),
            public_input: pi.clone(),
            eval_values_bytes: if i < folding_proof.gr1cs_proofs.len() {
                pipeline_cp_snark::encode_gr1cs_round_message(&folding_proof.gr1cs_proofs[i])
            } else {
                Vec::new()
            },
        })
        .collect();
    let fold_root = digest_fold_inputs(&fold_inputs);
    let fs_root = digest_fs_commitments(&fs_commitments);
    let transcript_seed_digest = digest_transcript_seed(
        &fixture.public_inputs,
        fixture.r1cs.num_constraints,
        fixture.r1cs.num_variables,
        fixture.r1cs.num_public,
    );

    CpPipelineMaterial {
        fs_commitments,
        fs_openings,
        fs_messages,
        folding_transcript_witness,
        fold_inputs,
        fold_root,
        fs_root,
        transcript_seed_digest,
        folded_instance: folding_proof.folded_instance,
        public_inputs: fixture.public_inputs.clone(),
        r1cs_num_constraints: fixture.r1cs.num_constraints,
        r1cs_num_variables: fixture.r1cs.num_variables,
        r1cs_num_public: fixture.r1cs.num_public,
    }
}

fn bind_cp_public_transcript(material: &CpPipelineMaterial, transcript: &mut Transcript) {
    for pi in &material.public_inputs {
        let bytes: Vec<u8> = pi.iter().flat_map(|v| v.to_le_bytes()).collect();
        transcript.append_bytes(b"public-input", &bytes);
    }

    transcript.append_bytes(
        b"r1cs-m",
        &(material.r1cs_num_constraints as u64).to_le_bytes(),
    );
    transcript.append_bytes(
        b"r1cs-n",
        &(material.r1cs_num_variables as u64).to_le_bytes(),
    );
    transcript.append_bytes(
        b"r1cs-pub",
        &(material.r1cs_num_public as u64).to_le_bytes(),
    );

    for fs_comm in &material.fs_commitments {
        transcript.append_bytes(b"fs-commitment", fs_comm);
    }
}

fn derive_cp_challenges(transcript: &mut Transcript, num_rounds: usize) -> Vec<Vec<u8>> {
    let mut derived_challenges = Vec::with_capacity(num_rounds);
    for i in 0..num_rounds {
        let mut challenge = vec![0u8; 32];
        let label = format!("challenge-{i}");
        transcript.challenge_bytes(label.as_bytes(), &mut challenge);
        derived_challenges.push(challenge);
    }
    derived_challenges
}

fn encode_cp_instance_compressed(material: &CpPipelineMaterial) -> Vec<u8> {
    let mut transcript = Transcript::new(b"symphony-v1");
    bind_cp_public_transcript(material, &mut transcript);
    let derived_challenges = derive_cp_challenges(&mut transcript, material.fs_commitments.len());
    let challenge_digest = digest_challenges(&derived_challenges);

    pipeline_cp_snark::encode_cp_instance_compressed(
        &material.fold_root,
        &material.folded_instance,
        &challenge_digest,
        &material.fs_root,
        &material.transcript_seed_digest,
    )
}

/// Legacy (linear) CP relation I/O encoding.
fn encode_cp_relation_io(material: &CpPipelineMaterial) -> (Vec<u8>, Vec<u8>) {
    let mut transcript = Transcript::new(b"symphony-v1");
    bind_cp_public_transcript(material, &mut transcript);

    let cp_instance = pipeline_cp_snark::encode_cp_instance(
        &material.fs_commitments,
        &material.folded_instance,
        &mut transcript,
    );

    let cp_witness = pipeline_cp_snark::encode_cp_witness(
        &material.fs_openings,
        &material.folding_transcript_witness,
    );

    (cp_instance, cp_witness)
}

/// Compressed (sublinear) CP relation I/O encoding, mirroring prover logic.
fn encode_cp_relation_io_compressed(material: &CpPipelineMaterial) -> (Vec<u8>, Vec<u8>) {
    let cp_instance = encode_cp_instance_compressed(material);
    let cp_witness = pipeline_cp_snark::encode_cp_witness_compressed(
        &material.fs_openings,
        &material.folding_transcript_witness,
        &material.fold_inputs,
        &material.fold_root,
        &material.fs_commitments,
        &material.fs_messages,
        &material.fs_root,
    );
    (cp_instance, cp_witness)
}

fn spartan_proof_wire_bytes(proof: &SpartanProof) -> usize {
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
fn whir_proof_wire_bytes(proof: &WhirProof) -> usize {
    let mut size = 0usize;
    size += proof.sumcheck_rounds_3.len() * 12;
    size += proof.sumcheck_rounds_4.len() * 16;
    size += 12;
    size += 4;
    size += 8;
    size += 1;
    size += 32 + proof.whir_pcs_proof.rounds.len() * 256;
    size
}

// -----------------------------------------------------------------------------
// Primitive benchmarks (kept for baseline context)
// -----------------------------------------------------------------------------

fn bench_ring_mul(c: &mut Criterion) {
    let a = RingElement::from_constant(42);
    let b = RingElement::monomial(3);
    let q = 12289u64;

    c.bench_function("ring_mul_schoolbook", |bencher| {
        bencher.iter(|| a.mul(&b, q));
    });
}

fn bench_ntt_ring_mul(c: &mut Criterion) {
    use symphony::ring::ntt::NttContext;

    let q = 12289u64;
    let ctx = NttContext::new(q);
    let a = RingElement::from_constant(42);
    let b = RingElement::monomial(3);

    c.bench_function("ring_mul_ntt", |bencher| {
        bencher.iter(|| ctx.ring_mul(&a, &b));
    });
}

fn bench_commitment(c: &mut Criterion) {
    let kappa = 4;
    let n = 64;
    let q = 12289u64;
    let ntt = NttContext::new(q);
    let params = AjtaiParams::setup(kappa, n, q, &ntt);
    let witness = RingVector {
        elements: (0..n)
            .map(|i| RingElement::from_constant(i as i64))
            .collect(),
    };

    c.bench_function("ajtai_commit_64", |bencher| {
        bencher.iter(|| params.commit(&witness));
    });
}

fn bench_decomposition(c: &mut Criterion) {
    use symphony::decomposition;

    c.bench_function("gadget_decompose_16_16", |bencher| {
        bencher.iter(|| decomposition::decompose(123456789, 16, 16));
    });
}

fn bench_sumcheck_prove(c: &mut Criterion) {
    let q = 257u64;
    let ctx = ExtFieldContext::new(q);
    let s = vec![
        ExtFieldElement { c0: 3, c1: 1 },
        ExtFieldElement { c0: 5, c1: 2 },
        ExtFieldElement { c0: 7, c1: 0 },
    ];
    let g: Vec<ExtFieldElement> = (0..8)
        .map(|i| ExtFieldElement {
            c0: (i * 3 + 1) as i64,
            c1: i as i64,
        })
        .collect();
    let eq = prover::build_eq_table(&s, &ctx);
    let challenges = vec![
        ExtFieldElement { c0: 11, c1: 2 },
        ExtFieldElement { c0: 13, c1: 5 },
        ExtFieldElement { c0: 17, c1: 1 },
    ];

    c.bench_function("sumcheck_prove_bookkeeping_3vars", |bencher| {
        bencher.iter_batched(
            || {
                let tables = vec![eq.clone(), g.clone()];
                let combiner = |f: &[ExtFieldElement], ctx: &ExtFieldContext| ctx.mul(&f[0], &f[1]);
                (tables, combiner)
            },
            |(mut tables, combiner)| {
                let proof = prover::prove_bookkeeping(
                    black_box(&mut tables),
                    black_box(&combiner),
                    black_box(3),
                    black_box(2),
                    black_box(&challenges),
                    black_box(&ctx),
                );
                black_box(proof);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_sumcheck_verify(c: &mut Criterion) {
    let q = 257u64;
    let ctx = ExtFieldContext::new(q);
    let s = vec![
        ExtFieldElement { c0: 3, c1: 1 },
        ExtFieldElement { c0: 5, c1: 2 },
        ExtFieldElement { c0: 7, c1: 0 },
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

    c.bench_function("sumcheck_verify_3vars", |bencher| {
        bencher.iter(|| {
            let ok = sumcheck::verifier::verify(
                black_box(&proof),
                black_box(&claim),
                black_box(&challenges),
                black_box(&ctx),
            );
            black_box(ok.is_ok());
        })
    });
}

// -----------------------------------------------------------------------------
// Scaling benchmarks requested by architecture review.
// -----------------------------------------------------------------------------

fn bench_scaling_folding_prove_k_statements(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling/folding_prove_k_statements");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let (r1cs, z) = multi_r1cs();
    let n_in = r1cs.num_public;

    for &k in SCALING_KS {
        let params = bench_params(k);
        let ntt = NttContext::new(params.q);
        let ajtai = AjtaiParams::setup(params.kappa, params.n(), params.q, &ntt);
        let rp = range_params();
        let ext_ctx = ExtFieldContext::new(params.q);

        let statements: Vec<FoldingStatement> = (0..k)
            .map(|_| make_folding_statement(&z, n_in, &ajtai))
            .collect();

        let (_, diag) = measure_resources(|| {
            let out = symphony::folding::prove(&statements, &r1cs, &ajtai, &rp, &ext_ctx);
            black_box(out)
        });
        record_scaling_row(
            "folding_prove",
            k,
            &diag,
            folding_pass_count_model(),
            "non_streaming_folding_path",
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("prove", k), |bencher| {
            bencher.iter(|| {
                let out = symphony::folding::prove(
                    black_box(&statements),
                    black_box(&r1cs),
                    black_box(&ajtai),
                    black_box(&rp),
                    black_box(&ext_ctx),
                );
                black_box(out);
            });
        });
    }

    group.finish();
}

fn bench_scaling_commit_witness_k_statements(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling/commit_witness_k_statements");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(8));

    let (_, z) = multi_r1cs();

    for &k in SCALING_KS {
        let params = bench_params(k);
        let (prover, _) = SymphonyProver::<SumcheckSnark>::setup(params);

        let full_witness = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };

        let (_, diag) = measure_resources(|| {
            for _ in 0..k {
                let out = prover.commit_witness(&full_witness);
                black_box(out);
            }
        });
        record_scaling_row(
            "commit_witness_batch",
            k,
            &diag,
            1,
            "single_statement_pass_over_batch",
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("commit_batch", k), |bencher| {
            bencher.iter(|| {
                for _ in 0..k {
                    let out = prover.commit_witness(black_box(&full_witness));
                    black_box(out);
                }
            });
        });
    }

    group.finish();
}

fn bench_scaling_pipeline_prove_verify_k(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling/pipeline_sumcheck_k_statements");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(12));

    for &k in SCALING_KS {
        let fixture = build_pipeline_fixture_sumcheck(k);
        let proof = fixture.prover.prove(&fixture.statements, &fixture.r1cs);
        assert!(fixture
            .verifier
            .verify(&fixture.public_inputs, &proof, &fixture.r1cs));

        let (_, diag_prove) = measure_resources(|| {
            let out = fixture.prover.prove(&fixture.statements, &fixture.r1cs);
            black_box(out)
        });
        record_scaling_row(
            "pipeline_prove",
            k,
            &diag_prove,
            pipeline_prove_pass_count_model(),
            "real_backend=sumcheck",
        );

        let (_, diag_verify) = measure_resources(|| {
            let ok = fixture
                .verifier
                .verify(&fixture.public_inputs, &proof, &fixture.r1cs);
            black_box(ok)
        });
        record_scaling_row(
            "pipeline_verify",
            k,
            &diag_verify,
            pipeline_verify_pass_count_model(),
            "real_backend=sumcheck",
        );

        group.throughput(Throughput::Elements(k as u64));

        group.bench_function(BenchmarkId::new("prove", k), |bencher| {
            bencher.iter(|| {
                let out = fixture
                    .prover
                    .prove(black_box(&fixture.statements), black_box(&fixture.r1cs));
                black_box(out);
            });
        });

        group.bench_function(BenchmarkId::new("verify", k), |bencher| {
            bencher.iter(|| {
                let ok = fixture.verifier.verify(
                    black_box(&fixture.public_inputs),
                    black_box(&proof),
                    black_box(&fixture.r1cs),
                );
                black_box(ok);
            });
        });
    }

    group.finish();
}

fn bench_scaling_cp_snark_inside_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling/cp_snark_inside_pipeline_sumcheck");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &k in SCALING_KS {
        let fixture = build_pipeline_fixture_sumcheck(k);
        let material = build_cp_pipeline_material(&fixture);
        let (cp_instance, cp_witness) = encode_cp_relation_io(&material);

        let cp_proof = SumcheckSnark::prove(&fixture.prover.cp_pk, &cp_instance, &cp_witness);
        assert!(SumcheckSnark::verify(
            &fixture.verifier.cp_vk,
            &cp_instance,
            &cp_proof
        ));

        let (_, diag_cp_prove) = measure_resources(|| {
            let (instance, witness) = encode_cp_relation_io(&material);
            let out = SumcheckSnark::prove(&fixture.prover.cp_pk, &instance, &witness);
            black_box(out)
        });
        record_scaling_row(
            "cp_pipeline_prove",
            k,
            &diag_cp_prove,
            cp_pipeline_prove_pass_count_model(),
            "cp_relation_only_with_real_backend",
        );

        let (_, diag_cp_verify) = measure_resources(|| {
            let (instance, _witness) = encode_cp_relation_io(&material);
            let ok = SumcheckSnark::verify(&fixture.verifier.cp_vk, &instance, &cp_proof);
            black_box(ok)
        });
        record_scaling_row(
            "cp_pipeline_verify",
            k,
            &diag_cp_verify,
            cp_pipeline_verify_pass_count_model(),
            "cp_relation_only_with_real_backend",
        );

        group.throughput(Throughput::Elements(k as u64));

        group.bench_function(BenchmarkId::new("prove", k), |bencher| {
            bencher.iter(|| {
                let (instance, witness) = encode_cp_relation_io(black_box(&material));
                let out = SumcheckSnark::prove(
                    black_box(&fixture.prover.cp_pk),
                    black_box(&instance),
                    black_box(&witness),
                );
                black_box(out);
            });
        });

        group.bench_function(BenchmarkId::new("verify", k), |bencher| {
            bencher.iter(|| {
                let (instance, _witness) = encode_cp_relation_io(black_box(&material));
                let ok = SumcheckSnark::verify(
                    black_box(&fixture.verifier.cp_vk),
                    black_box(&instance),
                    black_box(&cp_proof),
                );
                black_box(ok);
            });
        });
    }

    group.finish();
}

#[derive(Clone, Copy)]
struct CpBackendMetrics {
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
}

fn run_cp_backend_once<S: BackendSnark, F: Fn(&S::Proof) -> usize>(
    pk: &S::ProvingKey,
    vk: &S::VerifyingKey,
    instance: &[u8],
    witness: &[u8],
    proof_size_fn: F,
) -> CpBackendMetrics {
    let prove_start = Instant::now();
    let proof = S::prove(pk, instance, witness);
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;

    let verify_start = Instant::now();
    let ok = S::verify(vk, instance, &proof);
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;
    assert!(ok, "CP verify must succeed in backend comparison bench");

    CpBackendMetrics {
        prove_ms,
        verify_ms,
        proof_bytes: proof_size_fn(&proof),
    }
}

fn bench_cp_backend_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling/cp_backend_comparison");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &k in SCALING_KS {
        // Build one CP material instance and compare backends on the exact same data.
        let base_fixture = build_pipeline_fixture_sumcheck(k);
        let material = build_cp_pipeline_material(&base_fixture);
        let (legacy_instance, legacy_witness) = encode_cp_relation_io(&material);
        let (compressed_instance, compressed_witness) = encode_cp_relation_io_compressed(&material);

        let (spartan_prover, spartan_verifier) = SymphonyProver::<SpartanSnark>::setup(bench_params(k));

        let linear_metrics = run_cp_backend_once::<SpartanSnark, _>(
            &spartan_prover.cp_pk,
            &spartan_verifier.cp_vk,
            &legacy_instance,
            &legacy_witness,
            spartan_proof_wire_bytes,
        );
        let sublinear_metrics = run_cp_backend_once::<SpartanSnark, _>(
            &spartan_prover.cp_pk,
            &spartan_verifier.cp_vk,
            &compressed_instance,
            &compressed_witness,
            spartan_proof_wire_bytes,
        );

        let linear_proof = SpartanSnark::prove(
            &spartan_prover.cp_pk,
            &legacy_instance,
            &legacy_witness,
        );
        assert!(SpartanSnark::verify(
            &spartan_verifier.cp_vk,
            &legacy_instance,
            &linear_proof
        ));

        let sublinear_proof = SpartanSnark::prove(
            &spartan_prover.cp_pk,
            &compressed_instance,
            &compressed_witness,
        );
        assert!(SpartanSnark::verify(
            &spartan_verifier.cp_vk,
            &compressed_instance,
            &sublinear_proof
        ));

        #[cfg(feature = "whir")]
        let whir_metrics = {
            let (whir_prover, whir_verifier) = SymphonyProver::<WhirSnark>::setup(bench_params(k));
            let metrics = run_cp_backend_once::<WhirSnark, _>(
                &whir_prover.cp_pk,
                &whir_verifier.cp_vk,
                &compressed_instance,
                &compressed_witness,
                whir_proof_wire_bytes,
            );

            let whir_proof = WhirSnark::prove(
                &whir_prover.cp_pk,
                &compressed_instance,
                &compressed_witness,
            );
            assert!(WhirSnark::verify(
                &whir_verifier.cp_vk,
                &compressed_instance,
                &whir_proof
            ));

            group.bench_function(BenchmarkId::new("whir_sublinear_prove", k), |bencher| {
                bencher.iter(|| {
                    let p = WhirSnark::prove(
                        black_box(&whir_prover.cp_pk),
                        black_box(&compressed_instance),
                        black_box(&compressed_witness),
                    );
                    black_box(p);
                });
            });
            group.bench_function(BenchmarkId::new("whir_sublinear_verify", k), |bencher| {
                bencher.iter(|| {
                    let ok = WhirSnark::verify(
                        black_box(&whir_verifier.cp_vk),
                        black_box(&compressed_instance),
                        black_box(&whir_proof),
                    );
                    black_box(ok);
                });
            });

            metrics
        };

        eprintln!("[cp_backend_compare] k={k}");
        eprintln!(
            "spartan_linear: prove_ms={:.3} verify_ms={:.3} proof_bytes={}",
            linear_metrics.prove_ms, linear_metrics.verify_ms, linear_metrics.proof_bytes
        );
        eprintln!(
            "spartan_sublinear: prove_ms={:.3} verify_ms={:.3} proof_bytes={}",
            sublinear_metrics.prove_ms, sublinear_metrics.verify_ms, sublinear_metrics.proof_bytes
        );
        #[cfg(feature = "whir")]
        eprintln!(
            "whir_sublinear: prove_ms={:.3} verify_ms={:.3} proof_bytes={}",
            whir_metrics.prove_ms, whir_metrics.verify_ms, whir_metrics.proof_bytes
        );
        #[cfg(not(feature = "whir"))]
        eprintln!("whir_sublinear: N/A (requires --features whir)");

        let linear_ratio_prove = linear_metrics.prove_ms / sublinear_metrics.prove_ms;
        let linear_ratio_verify = linear_metrics.verify_ms / sublinear_metrics.verify_ms;
        let linear_ratio_size =
            linear_metrics.proof_bytes as f64 / sublinear_metrics.proof_bytes as f64;

        #[cfg(feature = "whir")]
        eprintln!(
            "ratios_vs_spartan_sublinear: linear(prove={:.2}x verify={:.2}x size={:.2}x) whir(prove={:.2}x verify={:.2}x size={:.2}x)",
            linear_ratio_prove,
            linear_ratio_verify,
            linear_ratio_size,
            whir_metrics.prove_ms / sublinear_metrics.prove_ms,
            whir_metrics.verify_ms / sublinear_metrics.verify_ms,
            whir_metrics.proof_bytes as f64 / sublinear_metrics.proof_bytes as f64,
        );
        #[cfg(not(feature = "whir"))]
        eprintln!(
            "ratios_vs_spartan_sublinear: linear(prove={:.2}x verify={:.2}x size={:.2}x) whir(N/A)",
            linear_ratio_prove, linear_ratio_verify, linear_ratio_size
        );

        group.throughput(Throughput::Elements(k as u64));

        group.bench_function(BenchmarkId::new("spartan_linear_prove", k), |bencher| {
            bencher.iter(|| {
                let p = SpartanSnark::prove(
                    black_box(&spartan_prover.cp_pk),
                    black_box(&legacy_instance),
                    black_box(&legacy_witness),
                );
                black_box(p);
            });
        });
        group.bench_function(BenchmarkId::new("spartan_linear_verify", k), |bencher| {
            bencher.iter(|| {
                let ok = SpartanSnark::verify(
                    black_box(&spartan_verifier.cp_vk),
                    black_box(&legacy_instance),
                    black_box(&linear_proof),
                );
                black_box(ok);
            });
        });

        group.bench_function(BenchmarkId::new("spartan_sublinear_prove", k), |bencher| {
            bencher.iter(|| {
                let p = SpartanSnark::prove(
                    black_box(&spartan_prover.cp_pk),
                    black_box(&compressed_instance),
                    black_box(&compressed_witness),
                );
                black_box(p);
            });
        });
        group.bench_function(BenchmarkId::new("spartan_sublinear_verify", k), |bencher| {
            bencher.iter(|| {
                let ok = SpartanSnark::verify(
                    black_box(&spartan_verifier.cp_vk),
                    black_box(&compressed_instance),
                    black_box(&sublinear_proof),
                );
                black_box(ok);
            });
        });
    }

    group.finish();
}

fn bench_scaling_streaming_passes_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling/streaming_passes_and_memory");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(8));

    let (_, z) = multi_r1cs();

    for &k in SCALING_KS {
        let params = bench_params(k);
        let ntt = NttContext::new(params.q);
        let ajtai = AjtaiParams::setup(params.kappa, params.n(), params.q, &ntt);
        let ext_ctx = ExtFieldContext::new(params.q);

        let base_witness = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let witnesses: Vec<RingVector> = (0..k).map(|_| base_witness.clone()).collect();

        let (sumcheck_passes, diag) = measure_resources(|| {
            let mut prover = StreamingProver::new(ajtai.clone(), k);
            prover.set_ext_context(ext_ctx.clone());

            for witness in &witnesses {
                let _ = prover.feed_witness_commitment(witness);
            }

            let mut observed_sumcheck_passes = 0usize;
            while matches!(prover.phase(), StreamingPhase::Sumcheck { .. }) {
                observed_sumcheck_passes += 1;
                for (statement_idx, witness) in witnesses.iter().enumerate() {
                    prover.feed_witness_sumcheck(witness, statement_idx);
                }
            }

            for (statement_idx, witness) in witnesses.iter().enumerate() {
                prover.feed_witness_folding(witness, statement_idx);
            }

            let folded = prover.finish();
            black_box(folded);
            observed_sumcheck_passes
        });

        let total_passes = 1 + sumcheck_passes + 1;
        let theoretical_passes = streaming_total_passes(params.n());

        record_scaling_row(
            "streaming_full",
            k,
            &diag,
            total_passes,
            if total_passes == theoretical_passes {
                "matches_2_plus_loglogn_plus_2"
            } else {
                "observed_passes_deviate_from_model"
            },
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("full_streaming_cycle", k), |bencher| {
            bencher.iter(|| {
                let mut prover = StreamingProver::new(ajtai.clone(), k);
                prover.set_ext_context(ext_ctx.clone());

                for witness in &witnesses {
                    let _ = prover.feed_witness_commitment(black_box(witness));
                }

                while matches!(prover.phase(), StreamingPhase::Sumcheck { .. }) {
                    for (statement_idx, witness) in witnesses.iter().enumerate() {
                        prover.feed_witness_sumcheck(black_box(witness), statement_idx);
                    }
                }

                for (statement_idx, witness) in witnesses.iter().enumerate() {
                    prover.feed_witness_folding(black_box(witness), statement_idx);
                }

                let folded = prover.finish();
                black_box(folded);
            });
        });
    }

    group.finish();
}

// -----------------------------------------------------------------------------
// Existing backend micro-benchmarks (kept, now secondary to scaling groups).
// -----------------------------------------------------------------------------

fn bench_backend_micro<S: BackendSnark>(
    c: &mut Criterion,
    backend_name: &str,
    witness_sizes: &[usize],
    sample_size: usize,
    measurement_time: Duration,
) {
    let mut group = c.benchmark_group(format!("backend_micro/{backend_name}"));
    group.sample_size(sample_size);
    group.measurement_time(measurement_time);

    for &witness_size in witness_sizes {
        let instance_size = (witness_size / 4).max(64);
        let relation = RelationDescription {
            num_instance_vars: instance_size,
            num_witness_vars: witness_size,
            num_constraints: (witness_size / 32).max(4),
            context: None,
        };
        let (pk, vk) = S::setup(&relation);

        let instance: Vec<u8> = (0..instance_size)
            .map(|i| ((i * 17 + 13) % 251) as u8)
            .collect();
        let witness: Vec<u8> = (0..witness_size)
            .map(|i| ((i * 31 + 7) % 251) as u8)
            .collect();
        let proof = S::prove(&pk, &instance, &witness);

        group.bench_function(BenchmarkId::new("prove", witness_size), |bencher| {
            bencher.iter(|| {
                let p = S::prove(black_box(&pk), black_box(&instance), black_box(&witness));
                black_box(p);
            });
        });

        group.bench_function(BenchmarkId::new("verify", witness_size), |bencher| {
            bencher.iter(|| {
                let ok = S::verify(black_box(&vk), black_box(&instance), black_box(&proof));
                black_box(ok);
            });
        });
    }

    group.finish();
}

// -----------------------------------------------------------------------------
// Sublinear verifier benchmarks: CP instance size and verify time vs k
// -----------------------------------------------------------------------------

fn bench_scaling_cp_instance_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling/cp_instance_size_vs_k");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(6));

    for &k in SCALING_KS {
        let fixture = build_pipeline_fixture_sumcheck(k);
        let material = build_cp_pipeline_material(&fixture);

        // --- Legacy (linear) encoding size ---
        let (legacy_instance, _) = encode_cp_relation_io(&material);
        let legacy_size = legacy_instance.len();

        // --- Compressed encoding size ---
        let compressed_instance = encode_cp_instance_compressed(&material);
        let compressed_size = compressed_instance.len();

        // Record sizes to scaling CSV
        let size_stats = ResourceStats {
            elapsed: Duration::ZERO,
            peak_heap_bytes: legacy_size as u64,
            alloc_calls: compressed_size,
            allocated_bytes: 0,
        };
        record_scaling_row(
            "cp_instance_size",
            k,
            &size_stats,
            0,
            &format!(
                "legacy_bytes={legacy_size} compressed_bytes={compressed_size} ratio={:.2}",
                legacy_size as f64 / compressed_size as f64
            ),
        );

        eprintln!(
            "[cp_instance_size] k={k} legacy={legacy_size} compressed={compressed_size} ratio={:.2}x",
            legacy_size as f64 / compressed_size as f64
        );

        // Criterion benchmark: encode compressed instance
        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("encode_compressed", k), |bencher| {
            bencher.iter(|| {
                black_box(encode_cp_instance_compressed(black_box(&material)));
            });
        });
    }

    group.finish();
}

fn bench_scaling_verifier_compressed_vs_k(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling/verifier_compressed_vs_k");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(12));

    for &k in SCALING_KS {
        let fixture = build_pipeline_fixture_sumcheck(k);
        let proof = fixture.prover.prove(&fixture.statements, &fixture.r1cs);
        assert!(fixture
            .verifier
            .verify(&fixture.public_inputs, &proof, &fixture.r1cs));

        // Measure verification time with the compressed CP instance path
        let (_, diag_verify) = measure_resources(|| {
            let ok = fixture
                .verifier
                .verify(&fixture.public_inputs, &proof, &fixture.r1cs);
            black_box(ok)
        });
        record_scaling_row(
            "pipeline_verify_compressed",
            k,
            &diag_verify,
            2,
            "compressed_cp_instance",
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("verify", k), |bencher| {
            bencher.iter(|| {
                let ok = fixture.verifier.verify(
                    black_box(&fixture.public_inputs),
                    black_box(&proof),
                    black_box(&fixture.r1cs),
                );
                black_box(ok);
            });
        });
    }

    group.finish();
}

fn bench_backend_micro_dummy(c: &mut Criterion) {
    bench_backend_micro::<DummySnark>(c, "dummy", &[512, 2048], 30, Duration::from_secs(6));
}

fn bench_backend_micro_sumcheck(c: &mut Criterion) {
    bench_backend_micro::<SumcheckSnark>(c, "sumcheck", &[512, 2048], 10, Duration::from_secs(20));
}

fn bench_backend_micro_spartan(c: &mut Criterion) {
    bench_backend_micro::<SpartanSnark>(c, "spartan", &[512, 2048], 10, Duration::from_secs(20));
}

// -----------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_ring_mul,
    bench_ntt_ring_mul,
    bench_commitment,
    bench_decomposition,
    bench_sumcheck_prove,
    bench_sumcheck_verify,
    bench_scaling_commit_witness_k_statements,
    bench_scaling_folding_prove_k_statements,
    bench_scaling_pipeline_prove_verify_k,
    bench_scaling_cp_snark_inside_pipeline,
    bench_cp_backend_comparison,
    bench_scaling_cp_instance_size,
    bench_scaling_verifier_compressed_vs_k,
    bench_scaling_streaming_passes_memory,
    bench_backend_micro_dummy,
    bench_backend_micro_sumcheck,
    bench_backend_micro_spartan,
);
criterion_main!(benches);
