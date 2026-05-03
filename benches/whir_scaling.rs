//! WHIR-only scaling benchmarks.
//!
//! Run:
//!   cargo bench --bench whir_scaling --features whir
//!   cargo bench --bench whir_scaling --features whir -- "whir_cp_scaling"
//!   cargo bench --bench whir_scaling --features whir -- "folding_only_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "pipeline_whir_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "modular_pipeline_whir_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "typed_cp_prove_only_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "typed_cp_verify_only_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "typed_output_verify_only_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "public_proof_size_vs_k"
//!   SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
//!
//! Reset local Criterion history for this bench:
//!   rm -rf target/criterion/whir_scaling target/criterion/report/whir_scaling
//!
//! Groups:
//!   whir_scaling/whir_cp_scaling            – standalone CPSnark prove+verify (WHIR backend)
//!   whir_scaling/folding_only_vs_k          – backend-independent high-arity folding only
//!   whir_scaling/pipeline_whir_vs_k         – full pipeline prove+verify with WHIR vs k
//!   whir_scaling/modular_pipeline_whir_vs_k – split CP/output WHIR backends vs k
//!   whir_scaling/public_verify_v2_vs_k      – public-only WHIR+WHIR verification vs k
//!   whir_scaling/typed_cp_prove_only_vs_k   – typed CP backend proving only
//!   whir_scaling/typed_cp_verify_only_vs_k  – typed CP backend verification only
//!   whir_scaling/typed_output_verify_only_vs_k – typed output backend verification only
//!   whir_scaling/public_proof_size_vs_k     – public proof serialization size only

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use symphony::commitment::{AjtaiParams, Commitment};
use symphony::cp_backend_api::CpBackend;
use symphony::cp_snark::IdentityRelation;
use symphony::fiat_shamir::FSCommitment;
use symphony::folding::FoldingStatement;
use symphony::output_backend_api::OutputBackend;
use symphony::params::{SymphonyParams, D};
use symphony::proof_orchestrator::Prover;
use symphony::r1cs::R1CSMatrices;
use symphony::ring::extension::ExtFieldContext;
use symphony::ring::ntt::NttContext;
use symphony::ring::{RingElement, RingVector};
use symphony::rok::range_proof::RangeProofParams;
use symphony::snark::cp_snark::{
    generate_cp_r1cs, generate_typed_cp_digest_r1cs_compressed_fs_with_audit,
    generate_typed_cp_digest_r1cs_with_audit, typed_cp_digest_input_lengths_from_setup,
    TypedCpAuditBlockKind,
};
use symphony::snark::{BackendSnark, RelationDescription, TypedCpSetupDescriptor};
use symphony::{
    canonical_whir_proof_bytes, CPSnark, HashCommitment, PublicProofBundle, SumcheckSnark,
    WhirProvingKey, WhirSnark, WhirVerifyingKey,
};

const WHIR_CP_NUM_MESSAGES: usize = 8;
const WHIR_CP_WITNESS_SIZES: &[usize] = &[256, 512, 1024, 2048, 4096];
const FOLDING_KS: &[usize] = &[2, 4, 8, 16, 32];
const WHIR_PIPELINE_KS: &[usize] = &[2, 4, 8];
const DEFAULT_WHIR_PUBLIC_VERIFY_KS: &[usize] = &[1];

fn public_verify_ks() -> Vec<usize> {
    let Some(raw) = std::env::var("SYMPHONY_WHIR_PUBLIC_VERIFY_KS")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return DEFAULT_WHIR_PUBLIC_VERIFY_KS.to_vec();
    };

    let mut values = Vec::new();
    for token in raw.split([',', ' ', ';']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let k = token.parse::<usize>().unwrap_or_else(|err| {
            panic!("invalid SYMPHONY_WHIR_PUBLIC_VERIFY_KS value {token:?}: {err}")
        });
        assert!(
            k > 0,
            "SYMPHONY_WHIR_PUBLIC_VERIFY_KS values must be positive"
        );
        values.push(k);
    }

    assert!(
        !values.is_empty(),
        "SYMPHONY_WHIR_PUBLIC_VERIFY_KS did not contain any k values"
    );
    values.sort_unstable();
    values.dedup();
    values
}

fn criterion_filter_allows(group: &str) -> bool {
    let filters: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| !arg.starts_with("--"))
        .collect();
    if filters.is_empty() {
        return true;
    }

    let short = group.rsplit('/').next().unwrap_or(group);
    filters
        .iter()
        .any(|filter| group.contains(filter) || short.contains(filter))
}

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

fn range_params() -> RangeProofParams {
    RangeProofParams {
        lambda_pj: 4,
        ell_h: D,
        d_prime: 62,
        k_g: 2,
        input_bound: 1024,
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

fn public_r1cs() -> (R1CSMatrices, Vec<i64>) {
    let mut r1cs = R1CSMatrices::new(1, 3, 1);
    r1cs.a.insert(0, 1, 1);
    r1cs.b.insert(0, 2, 1);
    r1cs.c.insert(0, 0, 15);
    (r1cs, vec![1i64, 3, 5])
}

fn public_verify_params(ell_np: usize) -> SymphonyParams {
    SymphonyParams {
        q: 257,
        d: D,
        kappa: 2,
        ell_np,
        ell_h: D,
        lambda_pj: 1,
        n_bar: 3,
        m: 1,
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
    let (commitment, _) = ajtai.commit(&full_ring);
    let witness = RingVector {
        elements: z[n_in..]
            .iter()
            .map(|&v| RingElement::from_constant(v))
            .collect(),
    };

    FoldingStatement {
        commitment,
        public_input: z[..n_in].to_vec(),
        witness,
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

fn cp_public_instance_bytes(num_messages: usize, public_statement_len: usize) -> usize {
    8 + num_messages * (8 + 32) + 8 + public_statement_len + 32
}

fn cp_witness_bytes(num_messages: usize, max_message_size: usize) -> usize {
    8 + num_messages * (8 + max_message_size) + num_messages * 32
}

fn babybear_packed_len(byte_len: usize) -> usize {
    byte_len.div_ceil(3) + 1
}

fn configure_micro_group(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
) {
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(15));
    group.noise_threshold(0.05);
}

fn configure_pipeline_group(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
) {
    group.sample_size(12);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(20));
    group.noise_threshold(0.05);
}

#[derive(Clone)]
struct TypedCpProfile {
    public_inputs: usize,
    witness_variables: usize,
    rows: usize,
    compressed_public_inputs: usize,
    compressed_witness_variables: usize,
    compressed_rows: usize,
    whir_num_vars: usize,
    cp_proof_bytes: usize,
    output_proof_bytes: usize,
    public_envelope_bytes: usize,
    compressed_public_envelope_bytes: usize,
    audit_rows: Vec<(TypedCpAuditBlockKind, usize)>,
}

struct PublicWhirBenchFixture {
    k: usize,
    r1cs: R1CSMatrices,
    public_inputs: Vec<Vec<i64>>,
    proof: PublicProofBundle<WhirSnark, WhirSnark>,
    cp_statement: symphony::CpPublicStatement,
    cp_witness: symphony::CpWitnessBundle,
    verifier: symphony::proof_orchestrator::Verifier<WhirSnark, WhirSnark>,
    typed_cp_pk: WhirProvingKey,
    typed_cp_vk: WhirVerifyingKey,
    typed_output_vk: WhirVerifyingKey,
    profile: TypedCpProfile,
}

fn typed_cp_descriptor_for_profile(
    params: &SymphonyParams,
    ajtai: &AjtaiParams,
    r1cs: &R1CSMatrices,
) -> TypedCpSetupDescriptor {
    let ext_ctx = ExtFieldContext::new(params.q);
    let (cp_r1cs, cp_layout) = generate_cp_r1cs(
        params.ell_np,
        params.kappa,
        params.n_in,
        params.m,
        ext_ctx.alpha,
        params.q,
    );
    TypedCpSetupDescriptor {
        params: params.clone(),
        ajtai: ajtai.clone(),
        original_r1cs: r1cs.clone(),
        cp_r1cs,
        cp_layout,
    }
}

fn typed_cp_profile_from_descriptor(
    descriptor: &TypedCpSetupDescriptor,
    cp_proof: &symphony::WhirProof,
    output_proof: &symphony::WhirProof,
    public_envelope_bytes: usize,
    compressed_public_envelope_bytes: usize,
) -> TypedCpProfile {
    let lengths = typed_cp_digest_input_lengths_from_setup(
        descriptor.cp_layout.ell_np,
        descriptor.cp_layout.kappa,
        descriptor.cp_layout.n_in,
        descriptor.params.lambda_pj,
        descriptor.params.ell_h,
        descriptor.params.k_g(),
        &descriptor.original_r1cs,
    )
    .expect("public WHIR fixture must have typed CP digest lengths");
    let (typed_cp_r1cs, _typed_cp_layout, audit) = generate_typed_cp_digest_r1cs_with_audit(
        &descriptor.cp_r1cs,
        &descriptor.cp_layout,
        &descriptor.ajtai,
        &descriptor.original_r1cs,
        &lengths,
    );
    audit
        .validate_against(&typed_cp_r1cs)
        .expect("typed CP audit profile must match generated R1CS");
    let (compressed_typed_cp_r1cs, _compressed_typed_cp_layout, compressed_audit) =
        generate_typed_cp_digest_r1cs_compressed_fs_with_audit(
            &descriptor.cp_r1cs,
            &descriptor.cp_layout,
            &descriptor.ajtai,
            &descriptor.original_r1cs,
            &lengths,
        );
    compressed_audit
        .validate_against(&compressed_typed_cp_r1cs)
        .expect("compressed typed CP audit profile must match generated R1CS");

    let audit_rows = [
        TypedCpAuditBlockKind::CpFoldingCore,
        TypedCpAuditBlockKind::ByteConstraints,
        TypedCpAuditBlockKind::PoseidonDigestGadgets,
        TypedCpAuditBlockKind::Gr1csMessageReconstruction,
        TypedCpAuditBlockKind::RangeMonomialSemantics,
        TypedCpAuditBlockKind::ChallengeToBetaBinding,
        TypedCpAuditBlockKind::FoldedOutputDerivation,
        TypedCpAuditBlockKind::AjtaiOpeningChecks,
        TypedCpAuditBlockKind::OriginalR1csValidity,
        TypedCpAuditBlockKind::PublicInputBinding,
    ]
    .into_iter()
    .map(|kind| (kind, audit.row_count_by_kind(kind)))
    .collect();

    TypedCpProfile {
        public_inputs: typed_cp_r1cs.num_public,
        witness_variables: typed_cp_r1cs.num_variables - typed_cp_r1cs.num_public,
        rows: typed_cp_r1cs.num_constraints,
        compressed_public_inputs: compressed_typed_cp_r1cs.num_public,
        compressed_witness_variables: compressed_typed_cp_r1cs.num_variables
            - compressed_typed_cp_r1cs.num_public,
        compressed_rows: compressed_typed_cp_r1cs.num_constraints,
        whir_num_vars: cp_proof.num_vars,
        cp_proof_bytes: canonical_whir_proof_bytes(cp_proof).len(),
        output_proof_bytes: canonical_whir_proof_bytes(output_proof).len(),
        public_envelope_bytes,
        compressed_public_envelope_bytes,
        audit_rows,
    }
}

fn audit_rows_for_log(profile: &TypedCpProfile) -> String {
    profile
        .audit_rows
        .iter()
        .map(|(kind, rows)| format!("{kind:?}={rows}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn print_public_profile(label: &str, fixture: &PublicWhirBenchFixture) {
    let profile = &fixture.profile;
    eprintln!(
        "[{label} k={}] typed_cp_public_inputs={} typed_cp_witness_variables={} \
         typed_cp_rows={} compressed_typed_cp_public_inputs={} \
         compressed_typed_cp_witness_variables={} compressed_typed_cp_rows={} \
         typed_cp_whir_num_vars={} cp_proof_bytes={} \
         output_proof_bytes={} public_envelope_bytes={} compressed_public_envelope_bytes={} \
         audit_rows={}",
        fixture.k,
        profile.public_inputs,
        profile.witness_variables,
        profile.rows,
        profile.compressed_public_inputs,
        profile.compressed_witness_variables,
        profile.compressed_rows,
        profile.whir_num_vars,
        profile.cp_proof_bytes,
        profile.output_proof_bytes,
        profile.public_envelope_bytes,
        profile.compressed_public_envelope_bytes,
        audit_rows_for_log(profile),
    );
}

fn public_whir_fixture(k: usize) -> PublicWhirBenchFixture {
    let (r1cs, z) = public_r1cs();
    let n_in = r1cs.num_public;
    let params = public_verify_params(k);
    let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(params.clone());
    let statements: Vec<_> = (0..k)
        .map(|_| make_modular_statement(&prover, &z, n_in))
        .collect();
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|(_, pi, _)| pi.clone()).collect();

    let full_proof = prover.prove(&statements, &r1cs);
    let proof = full_proof.to_v2();
    verifier
        .verify_public_attribution(&public_inputs, &proof, &r1cs)
        .unwrap_or_else(|stage| panic!("public WHIR fixture must verify for k={k}: {stage:?}"));

    let cp_statement = proof.cp_public_statement(
        &public_inputs,
        &r1cs,
        <WhirSnark as BackendSnark>::public_digest_scheme(),
    );
    let descriptor = typed_cp_descriptor_for_profile(&params, &prover.ajtai, &r1cs);
    let cp_relation = <WhirSnark as CpBackend>::typed_cp_relation_description(&descriptor)
        .expect("WHIR must provide typed CP relation for public fixture");
    let (typed_cp_pk, typed_cp_vk) = <WhirSnark as CpBackend>::setup(&cp_relation);

    let output_context =
        <WhirSnark as OutputBackend>::serialize_output_context(&r1cs, params.q, params.d)
            .expect("WHIR must provide typed output context for public fixture");
    let output_relation = RelationDescription {
        num_instance_vars: params.n(),
        num_witness_vars: params.n(),
        num_constraints: params.m,
        context: Some(output_context),
    };
    let (_, typed_output_vk) = <WhirSnark as OutputBackend>::setup(&output_relation);

    let cp_proof_bytes = canonical_whir_proof_bytes(&proof.cp_proof);
    let output_proof_bytes = canonical_whir_proof_bytes(&proof.output_proof);
    let public_envelope_bytes = proof
        .canonical_public_envelope_bytes(
            <WhirSnark as BackendSnark>::public_digest_scheme(),
            &public_inputs,
            &r1cs,
            &cp_proof_bytes,
            &output_proof_bytes,
        )
        .len();
    let compressed_public_envelope_bytes = proof
        .canonical_compressed_public_envelope_bytes(
            <WhirSnark as BackendSnark>::public_digest_scheme(),
            &public_inputs,
            &r1cs,
            &cp_proof_bytes,
            &output_proof_bytes,
        )
        .len();
    let profile = typed_cp_profile_from_descriptor(
        &descriptor,
        &proof.cp_proof,
        &proof.output_proof,
        public_envelope_bytes,
        compressed_public_envelope_bytes,
    );

    PublicWhirBenchFixture {
        k,
        r1cs,
        public_inputs,
        proof,
        cp_statement,
        cp_witness: full_proof.witness_bundle,
        verifier,
        typed_cp_pk,
        typed_cp_vk,
        typed_output_vk,
        profile,
    }
}

// ---------------------------------------------------------------------------
// 1. Standalone CPSnark with WHIR backend: prove + verify vs witness size
// ---------------------------------------------------------------------------

fn bench_whir_cp_scaling(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/whir_cp_scaling") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/whir_cp_scaling");
    configure_micro_group(&mut group);

    for &witness_size in WHIR_CP_WITNESS_SIZES {
        let num_messages = WHIR_CP_NUM_MESSAGES;
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

        let public_instance_bytes = cp_public_instance_bytes(num_messages, 0);
        let encoded_witness_bytes = cp_witness_bytes(num_messages, max_message_size);
        let proof_bytes =
            whir_proof_wire_bytes(&proof.backend_proof) + proof.transcript_digest.len();
        eprintln!(
            "[whir_cp_scaling] total_message_bytes={witness_size} \
             messages={num_messages} max_message_bytes={max_message_size} \
             public_instance_bytes={public_instance_bytes} \
             encoded_witness_bytes={encoded_witness_bytes} \
             packed_witness_elems~={} proof_bytes~={proof_bytes} \
             num_vars={} whir_rounds={}",
            babybear_packed_len(encoded_witness_bytes),
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
// 2. High-arity folding only: no CP/output backend work
// ---------------------------------------------------------------------------

fn bench_folding_only_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/folding_only_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/folding_only_vs_k");
    configure_pipeline_group(&mut group);

    let (r1cs, z) = multi_r1cs();
    let n_in = r1cs.num_public;
    let rp = range_params();

    for &k in FOLDING_KS {
        let params = bench_params(k);
        let ntt = NttContext::new(params.q);
        let ajtai = AjtaiParams::setup(params.kappa, params.n(), params.q, &ntt);
        let ext_ctx = ExtFieldContext::new(params.q);
        let statements: Vec<FoldingStatement> = (0..k)
            .map(|_| make_folding_statement(&z, n_in, &ajtai))
            .collect();

        let (folding_proof, _, _) =
            symphony::folding::prove(&statements, &r1cs, &ajtai, &rp, &ext_ctx);
        eprintln!(
            "[folding_only_vs_k k={k}] folded_public_inputs={} gr1cs_rounds={}",
            folding_proof.folded_instance.public_input.len(),
            folding_proof.gr1cs_proofs.len()
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("prove", k), |b| {
            b.iter(|| {
                let proof = symphony::folding::prove(
                    black_box(&statements),
                    black_box(&r1cs),
                    black_box(&ajtai),
                    black_box(&rp),
                    black_box(&ext_ctx),
                );
                black_box(proof);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 3. Full pipeline with homogeneous WHIR backend: prove + verify vs k
// ---------------------------------------------------------------------------

fn bench_pipeline_whir_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/pipeline_whir_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/pipeline_whir_vs_k");
    configure_pipeline_group(&mut group);

    let (r1cs, z) = multi_r1cs();
    let n_in = r1cs.num_public;

    for &k in WHIR_PIPELINE_KS {
        let params = bench_params(k);
        let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(params);

        let statements: Vec<(Commitment, Vec<i64>, RingVector)> = (0..k)
            .map(|_| make_snark_statement(&prover, &z, n_in))
            .collect();
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|(_, pi, _)| pi.clone()).collect();

        let proof = prover.prove(&statements, &r1cs);
        let verify_ok = verifier.verify(&public_inputs, &proof, &r1cs);
        eprintln!("[pipeline_whir_vs_k k={k}] verify={verify_ok}");
        if !verify_ok {
            eprintln!("[pipeline_whir_vs_k k={k}] skipping legacy full-verifier timing");
            continue;
        }

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
// 4. Modular pipeline with WHIR backend variants vs k
// ---------------------------------------------------------------------------

fn bench_modular_pipeline_whir_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/modular_pipeline_whir_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/modular_pipeline_whir_vs_k");
    configure_pipeline_group(&mut group);

    let (r1cs, z) = multi_r1cs();
    let n_in = r1cs.num_public;

    for &k in WHIR_PIPELINE_KS {
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
            if !verify_ok {
                eprintln!(
                    "[modular_pipeline k={k}] skipping whir+whir legacy full-verifier timing"
                );
                continue;
            }

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
            if !verify_ok {
                eprintln!("[modular_pipeline k={k}] skipping whir+sum legacy full-verifier timing");
                continue;
            }

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
// 5. Public v2 verifier with WHIR typed CP + WHIR typed output
// ---------------------------------------------------------------------------

fn bench_public_verify_v2_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/public_verify_v2_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/public_verify_v2_vs_k");
    configure_pipeline_group(&mut group);

    let (r1cs, _) = public_r1cs();
    let n_in = r1cs.num_public;
    let public_ks = public_verify_ks();
    eprintln!(
        "[public_verify_v2_vs_k] k_values={public_ks:?} default_k_values={DEFAULT_WHIR_PUBLIC_VERIFY_KS:?}"
    );

    for &k in &public_ks {
        let fixture = public_whir_fixture(k);
        debug_assert_eq!(fixture.r1cs.num_public, n_in);
        debug_assert_eq!(fixture.r1cs.num_constraints, r1cs.num_constraints);
        print_public_profile("public_verify_v2_vs_k", &fixture);
        let verify_ok =
            fixture
                .verifier
                .verify_public(&fixture.public_inputs, &fixture.proof, &fixture.r1cs);
        eprintln!("[public_verify_v2_vs_k k={k}] verify={verify_ok}");
        assert!(
            verify_ok,
            "public_verify_v2_vs_k produced invalid public proof for k={k}"
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("verify_public", k), |b| {
            b.iter(|| {
                black_box(fixture.verifier.verify_public(
                    black_box(&fixture.public_inputs),
                    black_box(&fixture.proof),
                    black_box(&fixture.r1cs),
                ));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 6. Typed CP/output public-verifier component profiling
// ---------------------------------------------------------------------------

fn bench_typed_cp_prove_only_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/typed_cp_prove_only_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/typed_cp_prove_only_vs_k");
    configure_pipeline_group(&mut group);

    for k in public_verify_ks() {
        let fixture = public_whir_fixture(k);
        print_public_profile("typed_cp_prove_only_vs_k", &fixture);
        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("prove_typed_cp", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::prove_typed_cp(
                        black_box(&fixture.typed_cp_pk),
                        black_box(&fixture.cp_statement),
                        black_box(&fixture.cp_witness),
                    )
                    .expect("WHIR typed CP proving must succeed"),
                );
            });
        });
    }

    group.finish();
}

fn bench_typed_cp_verify_only_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/typed_cp_verify_only_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/typed_cp_verify_only_vs_k");
    configure_pipeline_group(&mut group);

    for k in public_verify_ks() {
        let fixture = public_whir_fixture(k);
        print_public_profile("typed_cp_verify_only_vs_k", &fixture);
        let verify_ok = <WhirSnark as CpBackend>::verify_typed_cp(
            &fixture.typed_cp_vk,
            &fixture.cp_statement,
            &fixture.proof.cp_proof,
        )
        .unwrap_or(false);
        assert!(verify_ok, "WHIR typed CP proof must verify for k={k}");

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("verify_typed_cp", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::verify_typed_cp(
                        black_box(&fixture.typed_cp_vk),
                        black_box(&fixture.cp_statement),
                        black_box(&fixture.proof.cp_proof),
                    )
                    .unwrap_or(false),
                );
            });
        });
    }

    group.finish();
}

fn bench_typed_output_verify_only_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/typed_output_verify_only_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/typed_output_verify_only_vs_k");
    configure_pipeline_group(&mut group);

    for k in public_verify_ks() {
        let fixture = public_whir_fixture(k);
        print_public_profile("typed_output_verify_only_vs_k", &fixture);
        let verify_ok = <WhirSnark as OutputBackend>::verify_typed_output(
            &fixture.typed_output_vk,
            &fixture.proof.folded_output,
            &fixture.proof.output_proof,
        )
        .unwrap_or(false);
        assert!(verify_ok, "WHIR typed output proof must verify for k={k}");

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("verify_typed_output", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as OutputBackend>::verify_typed_output(
                        black_box(&fixture.typed_output_vk),
                        black_box(&fixture.proof.folded_output),
                        black_box(&fixture.proof.output_proof),
                    )
                    .unwrap_or(false),
                );
            });
        });
    }

    group.finish();
}

fn bench_public_proof_size_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/public_proof_size_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/public_proof_size_vs_k");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));
    group.noise_threshold(0.05);

    for k in public_verify_ks() {
        let fixture = public_whir_fixture(k);
        print_public_profile("public_proof_size_vs_k", &fixture);
        let cp_proof_bytes = canonical_whir_proof_bytes(&fixture.proof.cp_proof);
        let output_proof_bytes = canonical_whir_proof_bytes(&fixture.proof.output_proof);

        group.throughput(Throughput::Bytes(
            fixture.profile.public_envelope_bytes as u64,
        ));
        group.bench_function(BenchmarkId::new("canonical_envelope_bytes", k), |b| {
            b.iter(|| {
                black_box(fixture.proof.canonical_public_envelope_bytes(
                    black_box(<WhirSnark as BackendSnark>::public_digest_scheme()),
                    black_box(&fixture.public_inputs),
                    black_box(&fixture.r1cs),
                    black_box(&cp_proof_bytes),
                    black_box(&output_proof_bytes),
                ));
            });
        });

        group.throughput(Throughput::Bytes(
            fixture.profile.compressed_public_envelope_bytes as u64,
        ));
        group.bench_function(BenchmarkId::new("compressed_envelope_bytes", k), |b| {
            b.iter(|| {
                black_box(fixture.proof.canonical_compressed_public_envelope_bytes(
                    black_box(<WhirSnark as BackendSnark>::public_digest_scheme()),
                    black_box(&fixture.public_inputs),
                    black_box(&fixture.r1cs),
                    black_box(&cp_proof_bytes),
                    black_box(&output_proof_bytes),
                ));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_whir_cp_scaling,
    bench_folding_only_vs_k,
    bench_pipeline_whir_vs_k,
    bench_modular_pipeline_whir_vs_k,
    bench_public_verify_v2_vs_k,
    bench_typed_cp_prove_only_vs_k,
    bench_typed_cp_verify_only_vs_k,
    bench_typed_output_verify_only_vs_k,
    bench_public_proof_size_vs_k,
);
criterion_main!(benches);
