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
//!   cargo bench --bench whir_scaling --features whir -- "batched_cp_shape_profile_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "batched_cp_verify_only_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "batched_cp_product_oracle_whir_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "batched_cp_semantic_whir_v2_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "batched_cp_semantic_columnar_v2_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "batched_cp_semantic_columnar_poseidon_v2_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "batched_cp_semantic_family_columnar_v2_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "batched_cp_semantic_family_columnar_poseidon_v2_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "public_proof_batched_cp_size_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "symbt3_research_vs_product_verify_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "symbt3_accumulator_research_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "symbt3_accumulator_authority_vs_k"
//!   cargo bench --bench whir_scaling --features whir -- "product_route_comparison_vs_k"
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
//!   whir_scaling/batched_cp_shape_profile_vs_k – structured batched CP shape/manifest profiling
//!   whir_scaling/batched_cp_verify_only_vs_k – structured batched CP software evaluator only
//!   whir_scaling/batched_cp_product_oracle_whir_vs_k – SYMBTC1 WHIR oracle proof only
//!   whir_scaling/batched_cp_semantic_whir_v2_vs_k – SYMBTC2 full-selection semantic proof candidate
//!   whir_scaling/batched_cp_semantic_columnar_v2_vs_k – SYMBTC2 columnar residual skeleton
//!   whir_scaling/batched_cp_semantic_columnar_poseidon_v2_vs_k – SYMBT2C Poseidon/BabyBear residual skeleton
//!   whir_scaling/batched_cp_semantic_family_columnar_v2_vs_k – SYMBT2F family-local residual skeleton
//!   whir_scaling/batched_cp_semantic_family_columnar_poseidon_v2_vs_k – SYMBT2F Poseidon/BabyBear family-local skeleton
//!   whir_scaling/public_proof_batched_cp_size_vs_k – structured batched CP public-boundary size only
//!   whir_scaling/symbt3_research_vs_product_verify_vs_k – opt-in side-by-side product verify_public vs SYMBT3 research-authority-candidate verify
//!   whir_scaling/symbt3_accumulator_research_vs_k – K4 NonZK research public accumulator API vs k
//!   whir_scaling/symbt3_accumulator_authority_vs_k – K6a opt-in NonZK integrity product route vs k
//!   whir_scaling/product_route_comparison_vs_k – K6b side-by-side monolithic product vs K6a NonZK integrity product route

use std::hint::black_box;
use std::io::Write;
use std::sync::Once;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use symphony::batched_cp::{
    BatchedCpBucket, BatchedCpEvaluator, BatchedCpItem, BatchedCpSemanticConstraintFamily,
    BatchedCpSemanticFamilyColumnarV2Table, BatchedCpSymbt3RelationDescription,
    BatchedCpSymbt3SetupDescriptor, ProductProofKind, Symbt3AccumulatorInstance,
    Symbt3AccumulatorWitness, Symbt3AuthorityProfile, Symbt3MessageSemanticLayout,
    Symbt3ProjectionMode, Symbt3RangeMode,
};
use symphony::commitment::{AjtaiParams, Commitment};
use symphony::cp_backend_api::CpBackend;
use symphony::cp_snark::IdentityRelation;
use symphony::fiat_shamir::FSCommitment;
use symphony::folding::FoldingStatement;
use symphony::output_backend_api::OutputBackend;
use symphony::params::{SymphonyParams, D};
use symphony::proof_orchestrator::{ProofBundle, Prover};
use symphony::r1cs::R1CSMatrices;
use symphony::ring::extension::ExtFieldContext;
use symphony::ring::ntt::NttContext;
use symphony::ring::{RingElement, RingVector};
use symphony::rok::range_proof::RangeProofParams;
use symphony::snark::cp_snark::{
    generate_cp_r1cs, generate_typed_cp_digest_r1cs_compressed_fs_with_audit,
    generate_typed_cp_digest_r1cs_with_audit, typed_cp_digest_input_lengths_from_setup,
    TypedCpAuditBlockKind, TypedCpSplitComponent,
};
use symphony::snark::whir::{
    whir_typed_batched_cp_columnar_v2_private_opening_profile,
    whir_typed_batched_cp_family_columnar_v2_private_opening_profile,
    whir_typed_batched_cp_family_columnar_v2_verify_with_cache_stats,
    WhirBatchedCpColumnarV2OpeningProfile,
};
use symphony::snark::{BackendSnark, RelationDescription, TypedCpSetupDescriptor};
use symphony::{
    canonical_whir_proof_bytes,
    cp_relation_core::CpPublicStatement,
    digest_core::{
        derive_challenges_with_scheme, digest_challenge_digest_with_scheme,
        digest_domain_with_scheme, digest_fold_root_with_scheme, digest_fs_root_with_scheme,
        digest_transcript_seed_with_scheme, fs_commit_with_scheme, PublicDigestScheme,
    },
    CPSnark, HashCommitment, PublicProofBundle, SumcheckSnark, WhirProof, WhirProvingKey,
    WhirSnark, WhirVerifyingKey,
};

static SYMBT3_SCALING_CSV_INIT: Once = Once::new();
static PRODUCT_ROUTE_COMPARISON_CSV_INIT: Once = Once::new();

const PRODUCT_ROUTE_COMPARISON_CSV_PATH: &str = "benchmarks/product_route_comparison.csv";
const PRODUCT_ROUTE_COMPARISON_CSV_PREFIX: &str = "PRODUCT_COMPARISON_CSV,";
const PRODUCT_ROUTE_COMPARISON_CSV_HEADER: &str = concat!(
    "k,monolithic_verify_ms,symbt3_verify_ms,verify_speedup,",
    "monolithic_prove_ms,symbt3_prove_ms,prove_speedup,",
    "monolithic_proof_bytes,symbt3_proof_bytes,proof_size_ratio,",
    "monolithic_public_statement_bytes,symbt3_public_statement_bytes,",
    "public_size_ratio,symbt3_whir_num_vars,symbt3_oracle_len,",
    "symbt3_opened_field_elements,symbt3_top_level_whir_proof_count,",
    "symbt3_family_columnar_subproof_count,symbt3_backend_table_count,",
    "symbt3_accumulator_transition_claims,",
    "symbt3_source_r1cs_residual_verifier_evaluations,",
    "symbt3_product_route_selected,symbt3_monolithic_fallback_used\n"
);
const SYMBT3_TOP_LEVEL_WHIR_PROOF_COUNT: usize = 1;
const SYMBT3_BACKEND_TABLE_COUNT: usize = 1;
const SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER: usize = 0;

const WHIR_CP_NUM_MESSAGES: usize = 8;
const WHIR_CP_WITNESS_SIZES: &[usize] = &[256, 512, 1024, 2048, 4096];
const FOLDING_KS: &[usize] = &[2, 4, 8, 16, 32];
const WHIR_PIPELINE_KS: &[usize] = &[2, 4, 8];
const DEFAULT_WHIR_PUBLIC_VERIFY_KS: &[usize] = &[1];
const DEFAULT_PRODUCT_ROUTE_COMPARISON_KS: &[usize] = &[1, 2, 4, 8];

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

fn product_route_comparison_ks() -> Vec<usize> {
    if std::env::var("SYMPHONY_WHIR_PUBLIC_VERIFY_KS")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .is_some()
    {
        public_verify_ks()
    } else {
        DEFAULT_PRODUCT_ROUTE_COMPARISON_KS.to_vec()
    }
}

struct Symbt3ScalingCsvRow<'a> {
    profile: &'a str,
    route_kind: &'a str,
    k: usize,
    proof_bytes: usize,
    public_statement_bytes: usize,
    prove_ms: f64,
    verify_ms: f64,
    whir_num_vars: usize,
    oracle_len: usize,
    opened_field_elements: usize,
    sumcheck_rounds: usize,
    transcript_squeezes: usize,
    pcs_merkle_opening_proxy: usize,
    top_level_whir_proof_count: usize,
    family_columnar_subproof_count: usize,
    backend_table_count: usize,
    verify_whir_pcs_ms: f64,
    verify_transcript_ms: f64,
    verify_sumcheck_rounds_ms: f64,
    verify_final_constraint_eval_ms: f64,
    verify_manifest_membership_eval_ms: f64,
    verify_message_view_eval_ms: f64,
    verify_projection_eval_ms: f64,
    verify_monomial_embedding_eval_ms: f64,
    verify_representative_eval_ms: f64,
    verify_ajtai_eval_ms: f64,
    source_r1cs_residual_claims: usize,
    source_r1cs_residual_verifier_evaluations: usize,
    folded_gr1cs_boundary_claims: usize,
    folded_gr1cs_product_claims: usize,
    manifest_public_bytes: usize,
    manifest_logical_coordinates: usize,
    manifest_coordinate_count: usize,
    source_view_backend_column_count: usize,
    source_view_materialized_coordinate_count: usize,
    manifest_backend_column_count: usize,
    manifest_materialized_coordinate_count: usize,
    accumulator_transition_claims: usize,
    message_view_coordinates: usize,
    message_coordinate_count: usize,
    message_to_trace_binding_count: usize,
    verify_final_eval_manifest_ms: f64,
    verify_final_eval_source_r1cs_ms: f64,
    verify_final_eval_folded_boundary_ms: f64,
    verify_final_eval_product_residual_ms: f64,
    verify_final_eval_ajtai_ms: f64,
    verify_final_eval_range_ms: f64,
    verify_final_eval_message_view_ms: f64,
    product_route_selected: bool,
    monolithic_fallback_used: bool,
}

fn write_symbt3_scaling_csv_row(row: &Symbt3ScalingCsvRow<'_>) {
    const HEADER: &str = concat!(
        "profile,route_kind,k,proof_bytes,public_statement_bytes,prove_ms,verify_ms,",
        "whir_num_vars,oracle_len,opened_field_elements,sumcheck_rounds,",
        "transcript_squeezes,pcs_merkle_opening_proxy,top_level_whir_proof_count,",
        "family_columnar_subproof_count,backend_table_count,verify_whir_pcs_ms,",
        "verify_transcript_ms,verify_sumcheck_rounds_ms,verify_final_constraint_eval_ms,",
        "verify_manifest_membership_eval_ms,verify_message_view_eval_ms,",
        "verify_projection_eval_ms,verify_monomial_embedding_eval_ms,",
        "verify_representative_eval_ms,verify_ajtai_eval_ms,source_r1cs_residual_claims,",
        "source_r1cs_residual_verifier_evaluations,",
        "folded_gr1cs_boundary_claims,folded_gr1cs_product_claims,",
        "manifest_public_bytes,manifest_logical_coordinates,",
        "manifest_coordinate_count,source_view_backend_column_count,",
        "source_view_materialized_coordinate_count,manifest_backend_column_count,",
        "manifest_materialized_coordinate_count,",
        "accumulator_transition_claims,message_view_coordinates,",
        "message_coordinate_count,message_to_trace_binding_count,",
        "verify_final_eval_manifest_ms,verify_final_eval_source_r1cs_ms,",
        "verify_final_eval_folded_boundary_ms,verify_final_eval_product_residual_ms,",
        "verify_final_eval_ajtai_ms,verify_final_eval_range_ms,",
        "verify_final_eval_message_view_ms,product_route_selected,",
        "monolithic_fallback_used\n"
    );
    SYMBT3_SCALING_CSV_INIT.call_once(|| {
        std::fs::create_dir_all("benchmarks").expect("create benchmarks directory");
        std::fs::write("benchmarks/symbt3_scaling.csv", HEADER)
            .expect("write SYMBT3 scaling CSV header");
    });

    let fields = [
        row.profile.to_string(),
        row.route_kind.to_string(),
        row.k.to_string(),
        row.proof_bytes.to_string(),
        row.public_statement_bytes.to_string(),
        format!("{:.6}", row.prove_ms),
        format!("{:.6}", row.verify_ms),
        row.whir_num_vars.to_string(),
        row.oracle_len.to_string(),
        row.opened_field_elements.to_string(),
        row.sumcheck_rounds.to_string(),
        row.transcript_squeezes.to_string(),
        row.pcs_merkle_opening_proxy.to_string(),
        row.top_level_whir_proof_count.to_string(),
        row.family_columnar_subproof_count.to_string(),
        row.backend_table_count.to_string(),
        format!("{:.6}", row.verify_whir_pcs_ms),
        format!("{:.6}", row.verify_transcript_ms),
        format!("{:.6}", row.verify_sumcheck_rounds_ms),
        format!("{:.6}", row.verify_final_constraint_eval_ms),
        format!("{:.6}", row.verify_manifest_membership_eval_ms),
        format!("{:.6}", row.verify_message_view_eval_ms),
        format!("{:.6}", row.verify_projection_eval_ms),
        format!("{:.6}", row.verify_monomial_embedding_eval_ms),
        format!("{:.6}", row.verify_representative_eval_ms),
        format!("{:.6}", row.verify_ajtai_eval_ms),
        row.source_r1cs_residual_claims.to_string(),
        row.source_r1cs_residual_verifier_evaluations.to_string(),
        row.folded_gr1cs_boundary_claims.to_string(),
        row.folded_gr1cs_product_claims.to_string(),
        row.manifest_public_bytes.to_string(),
        row.manifest_logical_coordinates.to_string(),
        row.manifest_coordinate_count.to_string(),
        row.source_view_backend_column_count.to_string(),
        row.source_view_materialized_coordinate_count.to_string(),
        row.manifest_backend_column_count.to_string(),
        row.manifest_materialized_coordinate_count.to_string(),
        row.accumulator_transition_claims.to_string(),
        row.message_view_coordinates.to_string(),
        row.message_coordinate_count.to_string(),
        row.message_to_trace_binding_count.to_string(),
        format!("{:.6}", row.verify_final_eval_manifest_ms),
        format!("{:.6}", row.verify_final_eval_source_r1cs_ms),
        format!("{:.6}", row.verify_final_eval_folded_boundary_ms),
        format!("{:.6}", row.verify_final_eval_product_residual_ms),
        format!("{:.6}", row.verify_final_eval_ajtai_ms),
        format!("{:.6}", row.verify_final_eval_range_ms),
        format!("{:.6}", row.verify_final_eval_message_view_ms),
        row.product_route_selected.to_string(),
        row.monolithic_fallback_used.to_string(),
    ];
    let line = format!("{}\n", fields.join(","));
    print!("SYMBT3_CSV,{line}");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open("benchmarks/symbt3_scaling.csv")
        .expect("open SYMBT3 scaling CSV");
    file.write_all(line.as_bytes())
        .expect("append SYMBT3 scaling CSV row");
}

struct ProductRouteComparisonCsvRow {
    k: usize,
    monolithic_verify_ms: f64,
    symbt3_verify_ms: f64,
    monolithic_prove_ms: f64,
    symbt3_prove_ms: f64,
    monolithic_proof_bytes: usize,
    symbt3_proof_bytes: usize,
    monolithic_public_statement_bytes: usize,
    symbt3_public_statement_bytes: usize,
    symbt3_whir_num_vars: usize,
    symbt3_oracle_len: usize,
    symbt3_opened_field_elements: usize,
    symbt3_top_level_whir_proof_count: usize,
    symbt3_family_columnar_subproof_count: usize,
    symbt3_backend_table_count: usize,
    symbt3_accumulator_transition_claims: usize,
    symbt3_source_r1cs_residual_verifier_evaluations: usize,
    symbt3_product_route_selected: bool,
    symbt3_monolithic_fallback_used: bool,
}

fn ratio(numerator: f64, denominator: f64) -> f64 {
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

fn write_product_route_comparison_csv_row(row: &ProductRouteComparisonCsvRow) {
    PRODUCT_ROUTE_COMPARISON_CSV_INIT.call_once(|| {
        std::fs::create_dir_all("benchmarks").expect("create benchmarks directory");
        std::fs::write(
            PRODUCT_ROUTE_COMPARISON_CSV_PATH,
            PRODUCT_ROUTE_COMPARISON_CSV_HEADER,
        )
        .expect("write product route comparison CSV header");
    });

    let verify_speedup = ratio(row.monolithic_verify_ms, row.symbt3_verify_ms);
    let prove_speedup = ratio(row.monolithic_prove_ms, row.symbt3_prove_ms);
    let proof_size_ratio = ratio(
        row.symbt3_proof_bytes as f64,
        row.monolithic_proof_bytes as f64,
    );
    let public_size_ratio = ratio(
        row.symbt3_public_statement_bytes as f64,
        row.monolithic_public_statement_bytes as f64,
    );
    let fields = [
        row.k.to_string(),
        format!("{:.6}", row.monolithic_verify_ms),
        format!("{:.6}", row.symbt3_verify_ms),
        format!("{:.6}", verify_speedup),
        format!("{:.6}", row.monolithic_prove_ms),
        format!("{:.6}", row.symbt3_prove_ms),
        format!("{:.6}", prove_speedup),
        row.monolithic_proof_bytes.to_string(),
        row.symbt3_proof_bytes.to_string(),
        format!("{:.6}", proof_size_ratio),
        row.monolithic_public_statement_bytes.to_string(),
        row.symbt3_public_statement_bytes.to_string(),
        format!("{:.6}", public_size_ratio),
        row.symbt3_whir_num_vars.to_string(),
        row.symbt3_oracle_len.to_string(),
        row.symbt3_opened_field_elements.to_string(),
        row.symbt3_top_level_whir_proof_count.to_string(),
        row.symbt3_family_columnar_subproof_count.to_string(),
        row.symbt3_backend_table_count.to_string(),
        row.symbt3_accumulator_transition_claims.to_string(),
        row.symbt3_source_r1cs_residual_verifier_evaluations
            .to_string(),
        row.symbt3_product_route_selected.to_string(),
        row.symbt3_monolithic_fallback_used.to_string(),
    ];
    let line = format!("{}\n", fields.join(","));
    print!("{PRODUCT_ROUTE_COMPARISON_CSV_PREFIX}{line}");
    std::io::stdout()
        .flush()
        .expect("flush product route comparison CSV row");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(PRODUCT_ROUTE_COMPARISON_CSV_PATH)
        .expect("open product route comparison CSV");
    file.write_all(line.as_bytes())
        .expect("append product route comparison CSV row");
}

fn top_family_columnar_tables(tables: &[BatchedCpSemanticFamilyColumnarV2Table]) -> String {
    let mut ranked = tables
        .iter()
        .map(|table| {
            let num_vars = (table.column_kinds.len() * table.padded_row_count)
                .next_power_of_two()
                .max(2)
                .trailing_zeros() as usize;
            (
                num_vars,
                table.row_count,
                table.padded_row_count,
                format!("{:?}", table.family),
                table.label.clone(),
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|a, b| b.cmp(a));
    ranked
        .into_iter()
        .take(5)
        .map(|(num_vars, rows, padded_rows, family, label)| {
            format!("{family}:{label}:rows={rows},padded_rows={padded_rows},num_vars={num_vars}")
        })
        .collect::<Vec<_>>()
        .join("|")
}

#[derive(Default)]
struct FamilyColumnarAttribution {
    table_count: usize,
    subproof_count: usize,
    proof_bytes: usize,
    private_opening_evals: usize,
    sampled_checks: usize,
    query_count: usize,
    merkle_path_queries: usize,
    row_count: usize,
    padded_row_count: usize,
    max_num_vars: usize,
    transcript_label_bytes: usize,
}

fn family_subproof_payload_bytes(proof: &WhirProof, subproof_index: usize) -> usize {
    let Some(subproof) = proof.family_columnar_subproofs.get(subproof_index) else {
        return 0;
    };
    let pcs_bytes =
        serde_json::to_vec(&subproof.whir_pcs_proof).expect("WHIR PCS proof must serialize");
    // table_index + num_vars + z_eval + pcs_len + pcs_bytes, matching the
    // family-subproof section in canonical_whir_proof_bytes.
    8 + 8 + 4 + 8 + pcs_bytes.len()
}

fn family_columnar_attribution_profile(
    tables: &[BatchedCpSemanticFamilyColumnarV2Table],
    opening_profile: &WhirBatchedCpColumnarV2OpeningProfile,
    proof: &WhirProof,
) -> String {
    let mut by_family = std::collections::BTreeMap::<
        BatchedCpSemanticConstraintFamily,
        FamilyColumnarAttribution,
    >::new();
    for (entry, table) in opening_profile.families.iter().zip(tables) {
        let stats = by_family.entry(entry.family).or_default();
        let num_vars = entry.num_vars.unwrap_or_else(|| {
            (table.column_kinds.len() * table.padded_row_count)
                .next_power_of_two()
                .max(2)
                .trailing_zeros() as usize
        });
        stats.table_count += 1;
        stats.row_count += table.row_count;
        stats.padded_row_count += table.padded_row_count;
        stats.max_num_vars = stats.max_num_vars.max(num_vars);
        stats.private_opening_evals += entry.section.len;
        stats.sampled_checks += entry.sampled_check_count;
        stats.query_count += entry.sampled_check_count;
        stats.merkle_path_queries += entry.sampled_check_count;
        stats.transcript_label_bytes += table.label.len() + format!("{:?}", entry.family).len();
        stats.proof_bytes += entry.section.len * 4;
        if let Some(subproof_index) = entry.subproof_index {
            stats.subproof_count += 1;
            stats.proof_bytes += family_subproof_payload_bytes(proof, subproof_index);
        }
    }

    by_family
        .into_iter()
        .map(|(family, stats)| {
            format!(
                "{family:?}:tables={},subproofs={},proof_bytes~={},private_evals={},queries={},merkle_paths~={},rows={},padded_rows={},max_num_vars={},transcript_label_bytes={},prove_work~={},verify_work~={}",
                stats.table_count,
                stats.subproof_count,
                stats.proof_bytes,
                stats.private_opening_evals,
                stats.query_count,
                stats.merkle_path_queries,
                stats.row_count,
                stats.padded_row_count,
                stats.max_num_vars,
                stats.transcript_label_bytes,
                stats.padded_row_count,
                stats.proof_bytes + stats.merkle_path_queries * stats.max_num_vars.max(1),
            )
        })
        .collect::<Vec<_>>()
        .join("|")
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

fn batched_cp_columnar_dev_params() -> SymphonyParams {
    SymphonyParams {
        q: 257,
        d: D,
        kappa: 2,
        ell_np: 2,
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

fn batched_cp_columnar_poseidon_dev_params() -> SymphonyParams {
    const BB_P: u64 = 2_013_265_921;
    SymphonyParams {
        q: BB_P,
        d: D,
        kappa: 2,
        ell_np: 2,
        ell_h: D,
        lambda_pj: 4,
        n_bar: 4,
        m: 4,
        b: 16,
        k_cs: 1,
        n_in: 1,
        ntt: SymphonyParams::try_ntt(BB_P, D),
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

fn make_batched_cp_columnar_dev_item(
    prover: &Prover<SumcheckSnark, SumcheckSnark>,
    r1cs: &R1CSMatrices,
    z: &[i64],
    tag: u8,
) -> BatchedCpItem {
    let n_in = r1cs.num_public;
    let statements = vec![
        make_modular_statement(prover, z, n_in),
        make_modular_statement(prover, z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements
        .iter()
        .map(|statement| statement.1.clone())
        .collect();
    let proof: ProofBundle<SumcheckSnark, SumcheckSnark> = prover.prove(&statements, r1cs);
    let public = CpPublicStatement::new(
        proof.cp_public_instance.clone(),
        public_inputs,
        r1cs,
        PublicDigestScheme::Sha256,
    );
    BatchedCpItem {
        item_tag: [tag; 32],
        public,
        witness: proof.witness_bundle,
    }
}

fn poseidon_shape_batched_cp_item(
    mut item: BatchedCpItem,
    prover: &Prover<SumcheckSnark, SumcheckSnark>,
) -> BatchedCpItem {
    let scheme = PublicDigestScheme::Poseidon2BabyBear;
    let mut fs_commitments = Vec::with_capacity(item.witness.fs_messages.len());
    let mut fs_openings = Vec::with_capacity(item.witness.fs_messages.len());
    for message in &item.witness.fs_messages {
        let (commitment, opening) = fs_commit_with_scheme(scheme, message);
        fs_commitments.push(commitment.to_vec());
        fs_openings.push(opening.to_vec());
    }

    item.public.digest_scheme = scheme;
    item.witness.fs_commitments = fs_commitments;
    item.witness.fs_openings = fs_openings;
    item.public.instance.fs_root = digest_fs_root_with_scheme(scheme, &item.witness.fs_commitments);
    item.public.instance.fold_root =
        digest_fold_root_with_scheme(scheme, &item.witness.fold_inputs);
    let challenges = derive_challenges_with_scheme(
        scheme,
        &item.public.public_inputs,
        item.public.r1cs_num_constraints,
        item.public.r1cs_num_variables,
        item.public.r1cs_num_public,
        &item.witness.fs_commitments,
    );
    item.public.instance.challenge_digest =
        digest_challenge_digest_with_scheme(scheme, &challenges);
    let typed_beta =
        symphony::snark::cp_snark::typed_r1cs::poseidon_challenges_to_betas(&challenges)
            .expect("Poseidon challenges should map to typed beta");
    item.witness.folding_proof.beta = typed_beta;
    item.witness.folded_witness = symphony::folding::retarget_folding_proof_to_current_beta(
        &mut item.witness.folding_proof,
        &item.public.public_inputs,
        &item.witness.original_witnesses,
        prover.params.q,
        prover.params.ntt(),
    )
    .expect("Poseidon beta should retarget folded state");
    item.public.instance.x_folded = item.witness.folding_proof.folded_instance.clone();
    item.witness.folded_output = item.public.instance.x_folded.clone();
    item.public.instance.folded_output =
        symphony::folding::folded_output_instance_from_proof(&item.witness.folding_proof);
    item.witness.folded_output_instance = item.public.instance.folded_output.clone();
    item.witness.folded_output_witness =
        symphony::folding::folded_output_witness_from_folded(&item.witness.folded_witness);
    item.public.instance.transcript_seed_digest = digest_transcript_seed_with_scheme(
        scheme,
        &item.public.public_inputs,
        item.public.r1cs_num_constraints,
        item.public.r1cs_num_variables,
        item.public.r1cs_num_public,
    );
    item
}

fn batched_cp_columnar_dev_fixture(
    k: usize,
) -> (
    Prover<SumcheckSnark, SumcheckSnark>,
    R1CSMatrices,
    BatchedCpBucket,
) {
    assert!(
        (1..=255).contains(&k),
        "SYMBT2C columnar dev benchmark expects 1 <= k <= 255"
    );
    let params = batched_cp_columnar_dev_params();
    let (prover, _verifier) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params);
    let (r1cs, z) = multi_r1cs();
    let items = (0..k)
        .map(|idx| make_batched_cp_columnar_dev_item(&prover, &r1cs, &z, (idx + 1) as u8))
        .collect();
    let whir_parameter_digest = digest_domain_with_scheme(
        PublicDigestScheme::Sha256,
        b"whir-scaling-symbt2c-columnar-dev-params",
        b"batched-cp",
    );
    let bucket = BatchedCpBucket::new(items, whir_parameter_digest)
        .expect("SYMBT2C columnar dev fixture must batch same-shaped CP items");
    (prover, r1cs, bucket)
}

fn batched_cp_columnar_poseidon_dev_fixture(
    k: usize,
) -> (
    Prover<SumcheckSnark, SumcheckSnark>,
    R1CSMatrices,
    BatchedCpBucket,
) {
    assert!(
        (1..=255).contains(&k),
        "SYMBT2C Poseidon columnar dev benchmark expects 1 <= k <= 255"
    );
    let params = batched_cp_columnar_poseidon_dev_params();
    let (prover, _verifier) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params);
    let (r1cs, z) = multi_r1cs();
    let items = (0..k)
        .map(|idx| {
            let item = make_batched_cp_columnar_dev_item(&prover, &r1cs, &z, (idx + 1) as u8);
            poseidon_shape_batched_cp_item(item, &prover)
        })
        .collect();
    let whir_parameter_digest = digest_domain_with_scheme(
        PublicDigestScheme::Sha256,
        b"whir-scaling-symbt2c-columnar-poseidon-dev-params",
        b"batched-cp",
    );
    let bucket = BatchedCpBucket::new(items, whir_parameter_digest)
        .expect("SYMBT2C Poseidon columnar fixture must batch same-shaped CP items");
    (prover, r1cs, bucket)
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

fn configure_reporter_group(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
) {
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(100));
    group.measurement_time(Duration::from_secs(1));
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
    split_rows: Vec<(TypedCpSplitComponent, usize)>,
}

struct PublicWhirBenchFixture {
    k: usize,
    r1cs: R1CSMatrices,
    public_inputs: Vec<Vec<i64>>,
    proof: PublicProofBundle<WhirSnark, WhirSnark>,
    prove_ms: f64,
    cp_statement: symphony::CpPublicStatement,
    cp_witness: symphony::CpWitnessBundle,
    verifier: symphony::proof_orchestrator::Verifier<WhirSnark, WhirSnark>,
    ajtai: AjtaiParams,
    input_bound: u64,
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
        split_rows: audit.split_row_counts(),
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

fn split_rows_for_log(profile: &TypedCpProfile) -> String {
    profile
        .split_rows
        .iter()
        .map(|(component, rows)| format!("{component:?}={rows}"))
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
         audit_rows={} split_rows={}",
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
        split_rows_for_log(profile),
    );
}

fn batched_cp_items_from_fixture(fixture: &PublicWhirBenchFixture, k: usize) -> Vec<BatchedCpItem> {
    (0..k)
        .map(|idx| {
            let mut tag = [0u8; 32];
            tag[..8].copy_from_slice(&(idx as u64).to_le_bytes());
            BatchedCpItem {
                item_tag: tag,
                public: fixture.cp_statement.clone(),
                witness: fixture.cp_witness.clone(),
            }
        })
        .collect()
}

fn batched_cp_whir_parameter_digest() -> [u8; 32] {
    digest_domain_with_scheme(
        <WhirSnark as BackendSnark>::public_digest_scheme(),
        b"batched-cp-whir-parameter-digest",
        b"whir-scaling-benchmark-v1",
    )
}

fn batched_cp_bucket_from_fixture(fixture: &PublicWhirBenchFixture, k: usize) -> BatchedCpBucket {
    BatchedCpBucket::new(
        batched_cp_items_from_fixture(fixture, k),
        batched_cp_whir_parameter_digest(),
    )
    .expect("same-shape batched CP profile fixture must batch")
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

    let prove_start = std::time::Instant::now();
    let full_proof = prover.prove(&statements, &r1cs);
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;
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
        prove_ms,
        cp_statement,
        cp_witness: full_proof.witness_bundle,
        verifier,
        ajtai: prover.ajtai.clone(),
        input_bound: params.b_input(),
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

fn bench_batched_cp_shape_profile_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/batched_cp_shape_profile_vs_k") {
        return;
    }
    let mut group = c.benchmark_group("whir_scaling/batched_cp_shape_profile_vs_k");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));

    let base_fixture = public_whir_fixture(1);
    for k in public_verify_ks() {
        let items = batched_cp_items_from_fixture(&base_fixture, k);
        let bucket = batched_cp_bucket_from_fixture(&base_fixture, k);
        let manifest = bucket.manifest();
        let round_commitments = bucket.round_message_commitments();
        let public = bucket.public_statement();
        let structured_relation = bucket.shape.structured_relation_description();
        eprintln!(
            "[batched_cp_shape_profile_vs_k k={k}] shape_id={} batch_log_size={} \
             batch_capacity={} active_count={} product_domain_size={} manifest_bytes={} \
             round_message_commitments={} witness_oracle_rows={} round_message_oracles={} \
             structured_relation_id={} structured_relation_constraints={}",
            hex_digest(&bucket.shape.shape_id),
            bucket.shape.batch_log_size,
            bucket.shape.batch_capacity,
            bucket.shape.active_count,
            bucket.shape.product_domain_size(),
            manifest.body.len(),
            round_commitments.commitments.len(),
            bucket.witness_bundle().witness_oracle_rows.len(),
            bucket.witness_bundle().round_message_oracles.len(),
            hex_digest(&structured_relation.relation_id()),
            structured_relation
                .to_relation_description()
                .num_constraints,
        );
        black_box(public);

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("build_shape_manifest", k), |b| {
            b.iter(|| {
                let bucket = BatchedCpBucket::new(
                    black_box(items.clone()),
                    black_box(batched_cp_whir_parameter_digest()),
                )
                .expect("same-shape batched CP profile fixture must batch");
                black_box(bucket.public_statement());
                black_box(bucket.witness_bundle());
            });
        });
    }

    group.finish();
}

fn bench_batched_cp_verify_only_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/batched_cp_verify_only_vs_k") {
        return;
    }
    let mut group = c.benchmark_group("whir_scaling/batched_cp_verify_only_vs_k");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));

    let base_fixture = public_whir_fixture(1);
    for k in public_verify_ks() {
        let bucket = batched_cp_bucket_from_fixture(&base_fixture, k);
        let public = bucket.public_statement();
        let witness = bucket.witness_bundle();
        let verify_ok = BatchedCpEvaluator::check(
            &public,
            &witness,
            &base_fixture.ajtai,
            &base_fixture.r1cs,
            base_fixture.input_bound,
        )
        .is_ok();
        eprintln!(
            "[batched_cp_verify_only_vs_k k={k}] software_verify={} public_statement_bytes={} \
             witness_oracle_rows={} round_message_oracles={}",
            verify_ok,
            public.canonical_bytes().len(),
            witness.witness_oracle_rows.len(),
            witness.round_message_oracles.len(),
        );
        assert!(
            verify_ok,
            "batched CP software evaluator must pass for k={k}"
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("software_evaluator", k), |b| {
            b.iter(|| {
                black_box(
                    BatchedCpEvaluator::check(
                        black_box(&public),
                        black_box(&witness),
                        black_box(&base_fixture.ajtai),
                        black_box(&base_fixture.r1cs),
                        black_box(base_fixture.input_bound),
                    )
                    .is_ok(),
                );
            });
        });
    }

    group.finish();
}

fn bench_public_proof_batched_cp_size_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/public_proof_batched_cp_size_vs_k") {
        return;
    }
    let mut group = c.benchmark_group("whir_scaling/public_proof_batched_cp_size_vs_k");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));

    let base_fixture = public_whir_fixture(1);
    for k in public_verify_ks() {
        let bucket = batched_cp_bucket_from_fixture(&base_fixture, k);
        let public = bucket.public_statement();
        let public_bytes = public.canonical_bytes();
        let manifest = bucket.manifest();
        eprintln!(
            "[public_proof_batched_cp_size_vs_k k={k}] public_statement_bytes={} \
             manifest_body_bytes={} round_message_commitments={} shape_id={}",
            public_bytes.len(),
            manifest.body.len(),
            public.round_message_commitments.len(),
            hex_digest(&public.shape.shape_id),
        );

        group.throughput(Throughput::Bytes(public_bytes.len() as u64));
        group.bench_function(BenchmarkId::new("public_statement_bytes", k), |b| {
            b.iter(|| {
                black_box(public.canonical_bytes());
            });
        });
    }

    group.finish();
}

fn bench_batched_cp_product_oracle_whir_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/batched_cp_product_oracle_whir_vs_k") {
        return;
    }
    let mut group = c.benchmark_group("whir_scaling/batched_cp_product_oracle_whir_vs_k");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));

    let base_fixture = public_whir_fixture(1);
    for k in public_verify_ks() {
        let bucket = batched_cp_bucket_from_fixture(&base_fixture, k);
        let public = bucket.public_statement();
        let witness = bucket.witness_bundle();
        let relation =
            <WhirSnark as CpBackend>::typed_batched_cp_relation_description(&bucket.shape)
                .expect("WHIR should expose SYMBTC1 structured relation metadata");
        let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
        let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
            .expect("SYMBTC1 product-domain WHIR proof must be produced");
        let verify_ok = <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof)
            .unwrap_or(false);
        assert!(
            verify_ok,
            "SYMBTC1 product-domain WHIR proof must verify for k={k}"
        );
        eprintln!(
            "[batched_cp_product_oracle_whir_vs_k k={k}] verify={} proof_bytes={} \
             oracle_public_bytes={} product_oracle_bytes={} public_oracle_claims={} \
             whir_num_vars={} constraints={}",
            verify_ok,
            canonical_whir_proof_bytes(&proof).len(),
            public.canonical_bytes().len(),
            bucket
                .witness_bundle()
                .canonical_product_oracle_bytes(&bucket.shape)
                .expect("canonical product oracle bytes")
                .len(),
            bucket
                .shape
                .canonical_product_oracle_public_packed_claim_count_for_statement(&public)
                .expect("statement-specific public oracle claims"),
            proof.num_vars,
            relation.num_constraints,
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("prove_product_oracle", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::prove_typed_batched_cp(
                        black_box(&pk),
                        black_box(&public),
                        black_box(&witness),
                    )
                    .expect("SYMBTC1 product-domain WHIR proof must be produced"),
                );
            });
        });

        group.bench_function(BenchmarkId::new("verify_product_oracle", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::verify_typed_batched_cp(
                        black_box(&vk),
                        black_box(&public),
                        black_box(&proof),
                    )
                    .unwrap_or(false),
                );
            });
        });
    }

    group.finish();
}

fn bench_batched_cp_semantic_whir_v2_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/batched_cp_semantic_whir_v2_vs_k") {
        return;
    }
    let mut group = c.benchmark_group("whir_scaling/batched_cp_semantic_whir_v2_vs_k");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));

    let base_fixture = public_whir_fixture(1);
    for k in public_verify_ks() {
        let bucket = batched_cp_bucket_from_fixture(&base_fixture, k);
        let public = bucket.public_statement();
        let witness = bucket.witness_bundle();
        let semantic_v2 = bucket.shape.semantic_v2_relation_description(
            &base_fixture.ajtai,
            &base_fixture.r1cs,
            base_fixture.input_bound,
        );
        let relation = semantic_v2.to_relation_description();
        let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
        let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
            .expect("SYMBTC2 semantic WHIR proof candidate must be produced");
        let verify_ok = <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof)
            .unwrap_or(false);
        assert!(
            verify_ok,
            "SYMBTC2 semantic WHIR proof candidate must verify for k={k}"
        );
        let profile = symphony::snark::whir::whir_typed_batched_cp_private_opening_profile(
            &vk.seed,
            &vk.relation,
            &public,
        )
        .expect("SYMBTC2 private-opening profile");
        eprintln!(
            "[batched_cp_semantic_whir_v2_vs_k k={k}] verify={} proof_bytes={} \
             public_statement_bytes={} product_oracle_bytes={} whir_num_vars={} \
             semantic_columns={} residual_families={} private_openings={} \
             equality_openings={} poseidon_openings={} ajtai_openings={} original_r1cs_openings={}",
            verify_ok,
            canonical_whir_proof_bytes(&proof).len(),
            public.canonical_bytes().len(),
            bucket
                .witness_bundle()
                .canonical_product_oracle_bytes(&bucket.shape)
                .expect("canonical product oracle bytes")
                .len(),
            proof.num_vars,
            semantic_v2.v2_layout.semantic_column_count,
            semantic_v2.v2_layout.residual_family_count,
            profile.total_len,
            profile.equality.len,
            profile.poseidon_r1cs.len,
            profile.ajtai_opening.len,
            profile.original_r1cs.len,
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("prove_semantic_v2", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::prove_typed_batched_cp(
                        black_box(&pk),
                        black_box(&public),
                        black_box(&witness),
                    )
                    .expect("SYMBTC2 semantic WHIR proof candidate must be produced"),
                );
            });
        });

        group.bench_function(BenchmarkId::new("verify_semantic_v2", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::verify_typed_batched_cp(
                        black_box(&vk),
                        black_box(&public),
                        black_box(&proof),
                    )
                    .unwrap_or(false),
                );
            });
        });
    }

    group.finish();
}

fn bench_batched_cp_semantic_columnar_v2_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/batched_cp_semantic_columnar_v2_vs_k") {
        return;
    }
    let mut group = c.benchmark_group("whir_scaling/batched_cp_semantic_columnar_v2_vs_k");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));

    for k in public_verify_ks() {
        let (prover, r1cs, bucket) = batched_cp_columnar_dev_fixture(k);
        let public = bucket.public_statement();
        let witness = bucket.witness_bundle();
        let columnar_v2 = bucket.shape.semantic_columnar_v2_relation_description(
            &prover.ajtai,
            &r1cs,
            prover.params.b_input(),
        );
        let relation = columnar_v2.to_relation_description();
        let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
        let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
            .expect("SYMBTC2 columnar WHIR proof skeleton must be produced");
        let verify_ok = <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof)
            .unwrap_or(false);
        assert!(
            verify_ok,
            "SYMBTC2 columnar WHIR proof skeleton must verify for k={k}"
        );
        let opening_profile = whir_typed_batched_cp_columnar_v2_private_opening_profile(
            &vk.seed,
            &vk.relation,
            &public,
        )
        .expect("SYMBT2C opening profile");
        let residual_profile = opening_profile
            .families
            .iter()
            .map(|entry| {
                format!(
                    "{:?}:residuals={},checks={},evals={}",
                    entry.family,
                    entry.residual_count,
                    entry.sampled_check_count,
                    entry.section.len
                )
            })
            .collect::<Vec<_>>()
            .join("|");
        eprintln!(
            "[batched_cp_semantic_columnar_v2_vs_k k={k}] verify={} proof_bytes={} \
             public_statement_bytes={} semantic_columns={} column_rows={} residuals={} \
             private_openings={} whir_num_vars={} residual_profile={}",
            verify_ok,
            canonical_whir_proof_bytes(&proof).len(),
            public.canonical_bytes().len(),
            columnar_v2.columnar_layout.columns.len(),
            columnar_v2.columnar_layout.column_row_count,
            columnar_v2.columnar_layout.residuals.len(),
            proof.private_opening_evals.len(),
            proof.num_vars,
            residual_profile,
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("prove_columnar_v2", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::prove_typed_batched_cp(
                        black_box(&pk),
                        black_box(&public),
                        black_box(&witness),
                    )
                    .expect("SYMBTC2 columnar WHIR proof skeleton must be produced"),
                );
            });
        });

        group.bench_function(BenchmarkId::new("verify_columnar_v2", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::verify_typed_batched_cp(
                        black_box(&vk),
                        black_box(&public),
                        black_box(&proof),
                    )
                    .unwrap_or(false),
                );
            });
        });
    }

    group.finish();
}

fn bench_batched_cp_semantic_columnar_poseidon_v2_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/batched_cp_semantic_columnar_poseidon_v2_vs_k") {
        return;
    }
    let mut group = c.benchmark_group("whir_scaling/batched_cp_semantic_columnar_poseidon_v2_vs_k");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));

    for k in public_verify_ks() {
        let (prover, r1cs, bucket) = batched_cp_columnar_poseidon_dev_fixture(k);
        let public = bucket.public_statement();
        let witness = bucket.witness_bundle();
        let columnar_v2 = bucket.shape.semantic_columnar_v2_relation_description(
            &prover.ajtai,
            &r1cs,
            prover.params.b_input(),
        );
        let relation = columnar_v2.to_relation_description();
        let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
        let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
            .expect("SYMBT2C Poseidon columnar WHIR proof skeleton must be produced");
        let verify_ok = <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof)
            .unwrap_or(false);
        assert!(
            verify_ok,
            "SYMBT2C Poseidon columnar WHIR proof skeleton must verify for k={k}"
        );
        let opening_profile = whir_typed_batched_cp_columnar_v2_private_opening_profile(
            &vk.seed,
            &vk.relation,
            &public,
        )
        .expect("SYMBT2C Poseidon opening profile");
        let residual_profile = opening_profile
            .families
            .iter()
            .map(|entry| {
                format!(
                    "{:?}:residuals={},checks={},evals={}",
                    entry.family,
                    entry.residual_count,
                    entry.sampled_check_count,
                    entry.section.len
                )
            })
            .collect::<Vec<_>>()
            .join("|");
        eprintln!(
            "[batched_cp_semantic_columnar_poseidon_v2_vs_k k={k}] verify={} proof_bytes={} \
             public_statement_bytes={} semantic_columns={} column_rows={} residuals={} \
             private_openings={} whir_num_vars={} residual_profile={}",
            verify_ok,
            canonical_whir_proof_bytes(&proof).len(),
            public.canonical_bytes().len(),
            columnar_v2.columnar_layout.columns.len(),
            columnar_v2.columnar_layout.column_row_count,
            columnar_v2.columnar_layout.residuals.len(),
            proof.private_opening_evals.len(),
            proof.num_vars,
            residual_profile,
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("prove_columnar_poseidon_v2", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::prove_typed_batched_cp(
                        black_box(&pk),
                        black_box(&public),
                        black_box(&witness),
                    )
                    .expect("SYMBT2C Poseidon columnar WHIR proof skeleton must be produced"),
                );
            });
        });

        group.bench_function(BenchmarkId::new("verify_columnar_poseidon_v2", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::verify_typed_batched_cp(
                        black_box(&vk),
                        black_box(&public),
                        black_box(&proof),
                    )
                    .unwrap_or(false),
                );
            });
        });
    }

    group.finish();
}

fn bench_batched_cp_semantic_family_columnar_v2_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/batched_cp_semantic_family_columnar_v2_vs_k") {
        return;
    }
    let mut group = c.benchmark_group("whir_scaling/batched_cp_semantic_family_columnar_v2_vs_k");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));

    for k in public_verify_ks() {
        let (prover, r1cs, bucket) = batched_cp_columnar_dev_fixture(k);
        let public = bucket.public_statement();
        let witness = bucket.witness_bundle();
        let family_v2 = bucket
            .shape
            .semantic_family_columnar_v2_relation_description(
                &prover.ajtai,
                &r1cs,
                prover.params.b_input(),
            );
        let relation = family_v2.to_relation_description();
        let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
        let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
            .expect("SYMBT2F WHIR proof skeleton must be produced");
        let (verify_ok, cache_stats) =
            whir_typed_batched_cp_family_columnar_v2_verify_with_cache_stats(&vk, &public, &proof)
                .expect("SYMBT2F cache stats");
        assert!(
            verify_ok,
            "SYMBT2F WHIR proof skeleton must verify for k={k}"
        );
        let unique_num_vars = proof
            .family_columnar_subproofs
            .iter()
            .map(|subproof| subproof.num_vars)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let opening_profile = whir_typed_batched_cp_family_columnar_v2_private_opening_profile(
            &vk.seed,
            &vk.relation,
            &public,
        )
        .expect("SYMBT2F opening profile");
        let residual_profile = opening_profile
            .families
            .iter()
            .zip(&family_v2.family_layout.tables)
            .map(|(entry, table)| {
                format!(
                    "{:?}:rows={},padded_rows={},num_vars={},subproof={:?},checks={},evals={}",
                    entry.family,
                    table.row_count,
                    entry.padded_row_count.unwrap_or(table.padded_row_count),
                    entry.num_vars.unwrap_or_else(|| {
                        (table.column_kinds.len() * table.padded_row_count)
                            .next_power_of_two()
                            .max(2)
                            .trailing_zeros() as usize
                    }),
                    entry.subproof_index,
                    entry.sampled_check_count,
                    entry.section.len
                )
            })
            .collect::<Vec<_>>()
            .join("|");
        let max_table_num_vars = family_v2
            .family_layout
            .tables
            .iter()
            .map(|table| {
                (table.column_kinds.len() * table.padded_row_count)
                    .next_power_of_two()
                    .max(2)
                    .trailing_zeros() as usize
            })
            .max()
            .unwrap_or(0);
        let top_tables = top_family_columnar_tables(&family_v2.family_layout.tables);
        let family_attribution = family_columnar_attribution_profile(
            &family_v2.family_layout.tables,
            &opening_profile,
            &proof,
        );
        eprintln!(
            "[batched_cp_semantic_family_columnar_v2_vs_k k={k}] verify={} proof_bytes={} \
             public_statement_bytes={} family_tables={} total_family_fields={} \
             family_subproofs={} unique_num_vars={} infra_cache_hits={} infra_cache_misses={} \
             private_openings={} max_table_num_vars={} top_tables={} family_attribution={} \
             residual_profile={}",
            verify_ok,
            canonical_whir_proof_bytes(&proof).len(),
            public.canonical_bytes().len(),
            family_v2.family_layout.tables.len(),
            family_v2.family_layout.total_field_len,
            proof.family_columnar_subproofs.len(),
            unique_num_vars,
            cache_stats.hits,
            cache_stats.misses,
            proof.private_opening_evals.len(),
            max_table_num_vars,
            top_tables,
            family_attribution,
            residual_profile,
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("prove_family_columnar_v2", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::prove_typed_batched_cp(
                        black_box(&pk),
                        black_box(&public),
                        black_box(&witness),
                    )
                    .expect("SYMBT2F WHIR proof skeleton must be produced"),
                );
            });
        });

        group.bench_function(BenchmarkId::new("verify_family_columnar_v2", k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::verify_typed_batched_cp(
                        black_box(&vk),
                        black_box(&public),
                        black_box(&proof),
                    )
                    .unwrap_or(false),
                );
            });
        });
    }

    group.finish();
}

fn bench_batched_cp_semantic_family_columnar_poseidon_v2_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/batched_cp_semantic_family_columnar_poseidon_v2_vs_k")
    {
        return;
    }
    let mut group =
        c.benchmark_group("whir_scaling/batched_cp_semantic_family_columnar_poseidon_v2_vs_k");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));

    for k in public_verify_ks() {
        let (prover, r1cs, bucket) = batched_cp_columnar_poseidon_dev_fixture(k);
        let public = bucket.public_statement();
        let witness = bucket.witness_bundle();
        let family_v2 = bucket
            .shape
            .semantic_family_columnar_v2_relation_description(
                &prover.ajtai,
                &r1cs,
                prover.params.b_input(),
            );
        let relation = family_v2.to_relation_description();
        let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
        let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
            .expect("SYMBT2F Poseidon WHIR proof skeleton must be produced");
        let (verify_ok, cache_stats) =
            whir_typed_batched_cp_family_columnar_v2_verify_with_cache_stats(&vk, &public, &proof)
                .expect("SYMBT2F Poseidon cache stats");
        assert!(
            verify_ok,
            "SYMBT2F Poseidon WHIR proof skeleton must verify for k={k}"
        );
        let unique_num_vars = proof
            .family_columnar_subproofs
            .iter()
            .map(|subproof| subproof.num_vars)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let opening_profile = whir_typed_batched_cp_family_columnar_v2_private_opening_profile(
            &vk.seed,
            &vk.relation,
            &public,
        )
        .expect("SYMBT2F Poseidon opening profile");
        let residual_profile = opening_profile
            .families
            .iter()
            .zip(&family_v2.family_layout.tables)
            .map(|(entry, table)| {
                format!(
                    "{:?}:rows={},padded_rows={},num_vars={},subproof={:?},checks={},evals={}",
                    entry.family,
                    table.row_count,
                    entry.padded_row_count.unwrap_or(table.padded_row_count),
                    entry.num_vars.unwrap_or_else(|| {
                        (table.column_kinds.len() * table.padded_row_count)
                            .next_power_of_two()
                            .max(2)
                            .trailing_zeros() as usize
                    }),
                    entry.subproof_index,
                    entry.sampled_check_count,
                    entry.section.len
                )
            })
            .collect::<Vec<_>>()
            .join("|");
        let max_table_num_vars = family_v2
            .family_layout
            .tables
            .iter()
            .map(|table| {
                (table.column_kinds.len() * table.padded_row_count)
                    .next_power_of_two()
                    .max(2)
                    .trailing_zeros() as usize
            })
            .max()
            .unwrap_or(0);
        let top_tables = top_family_columnar_tables(&family_v2.family_layout.tables);
        let family_attribution = family_columnar_attribution_profile(
            &family_v2.family_layout.tables,
            &opening_profile,
            &proof,
        );
        eprintln!(
            "[batched_cp_semantic_family_columnar_poseidon_v2_vs_k k={k}] verify={} proof_bytes={} \
             public_statement_bytes={} family_tables={} total_family_fields={} \
             family_subproofs={} unique_num_vars={} infra_cache_hits={} infra_cache_misses={} \
             private_openings={} max_table_num_vars={} top_tables={} family_attribution={} \
             residual_profile={}",
            verify_ok,
            canonical_whir_proof_bytes(&proof).len(),
            public.canonical_bytes().len(),
            family_v2.family_layout.tables.len(),
            family_v2.family_layout.total_field_len,
            proof.family_columnar_subproofs.len(),
            unique_num_vars,
            cache_stats.hits,
            cache_stats.misses,
            proof.private_opening_evals.len(),
            max_table_num_vars,
            top_tables,
            family_attribution,
            residual_profile,
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(
            BenchmarkId::new("prove_family_columnar_poseidon_v2", k),
            |b| {
                b.iter(|| {
                    black_box(
                        <WhirSnark as CpBackend>::prove_typed_batched_cp(
                            black_box(&pk),
                            black_box(&public),
                            black_box(&witness),
                        )
                        .expect("SYMBT2F Poseidon WHIR proof skeleton must be produced"),
                    );
                });
            },
        );

        group.bench_function(
            BenchmarkId::new("verify_family_columnar_poseidon_v2", k),
            |b| {
                b.iter(|| {
                    black_box(
                        <WhirSnark as CpBackend>::verify_typed_batched_cp(
                            black_box(&vk),
                            black_box(&public),
                            black_box(&proof),
                        )
                        .unwrap_or(false),
                    );
                });
            },
        );
    }

    group.finish();
}

fn bench_symbt3_profile_vs_k(c: &mut Criterion, profile: &'static str) {
    let group_name = format!("whir_scaling/{profile}_vs_k");
    if !criterion_filter_allows(&group_name) {
        return;
    }
    let mut group = c.benchmark_group(group_name);
    let ks = public_verify_ks();
    let base_fixture = public_whir_fixture(1);
    let mut previous_oracle_len: Option<(usize, usize)> = None;

    for &k in &ks {
        let bucket = batched_cp_bucket_from_fixture(&base_fixture, k);
        let descriptor = BatchedCpSymbt3SetupDescriptor::new(
            bucket.shape.clone(),
            &base_fixture.ajtai,
            &base_fixture.r1cs,
            base_fixture.input_bound,
        );
        let relation = <WhirSnark as CpBackend>::symbt3_relation_description(&descriptor)
            .unwrap_or_else(|| panic!("WHIR exposes {profile} relation"));
        let decoded_relation = BatchedCpSymbt3RelationDescription::from_context_bytes(
            relation.context.as_ref().expect("SYMBT3 context"),
        )
        .unwrap_or_else(|_| panic!("{profile} context decodes"));
        let decoded_relation = symbt3_relation_for_bench_profile(decoded_relation, profile);
        let relation = decoded_relation.to_relation_description();
        let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
        let public = bucket.symbt3_public_statement_for_relation(&decoded_relation);
        let witness = bucket.symbt3_witness_for_relation(&decoded_relation);
        let prove_start = std::time::Instant::now();
        let proof = <WhirSnark as CpBackend>::prove_symbt3_batched_cp(&pk, &public, &witness)
            .unwrap_or_else(|| panic!("{profile} proof"));
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;
        let verify_start = std::time::Instant::now();
        let verify_ok = <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &proof)
            .unwrap_or(false);
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;
        assert!(verify_ok, "{profile} proof must verify for k={k}");
        let (_, verifier_profile) =
            WhirSnark::profile_symbt3_batched_cp_verifier(&vk, &public, &proof)
                .unwrap_or_else(|| panic!("{profile} verifier profile"));
        let source_r1cs_claims = public.source_assignment_roots.len()
            * decoded_relation.r1cs_evaluator_layout.num_constraints
            * D;
        let folded_gr1cs_claims = decoded_relation
            .gr1cs_residual_layout
            .folded_evaluation_coordinate_count;
        let folded_gr1cs_product_claims = decoded_relation
            .gr1cs_residual_layout
            .folded_evaluation_coordinate_count
            / 3;
        let manifest_component_count = decoded_relation.batch_manifest_layout.component_kinds.len();
        let manifest_coordinate_count = decoded_relation
            .batch_manifest_layout
            .source_column_layout
            .coordinate_count
            * public.active_count;
        let source_view_backend_column_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
        let source_view_materialized_coordinate_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
        let manifest_backend_column_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
        let manifest_materialized_coordinate_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
        let message_round_count = decoded_relation.message_semantic_layout.round_count;
        let message_coordinate_count = decoded_relation
            .message_semantic_layout
            .view_coordinate_count(public.active_count);
        let message_to_trace_binding_count = decoded_relation
            .message_semantic_layout
            .message_to_trace_binding_count();
        let sumcheck_transition_count = decoded_relation
            .message_semantic_layout
            .semantic_sumcheck_transition_count();
        let projection_output_len = decoded_relation
            .ajtai_norm_range_layout
            .projection_layout
            .output_len;
        let monomial_embedding_enabled = decoded_relation.ajtai_norm_range_layout.range_mode
            == symphony::batched_cp::Symbt3RangeMode::MonomialEmbeddingRangeV1;
        let monomial_witness_coords = if monomial_embedding_enabled {
            projection_output_len
        } else {
            0
        };
        let representative_coords = projection_output_len;
        let range_residual_coords = projection_output_len;
        let constraint_family_count = decoded_relation.oracle_layout.constraint_families.len();
        let oracle_len = 1usize << proof.num_vars;
        if let Some((previous_k, previous_len)) = previous_oracle_len {
            if k == previous_k * 2 {
                assert!(
                    oracle_len <= previous_len * 2,
                    "{profile} K0/J3 backend oracle length must not grow faster than 2x per k doubling: k={previous_k}->{k}, {previous_len}->{oracle_len}"
                );
            }
        }
        previous_oracle_len = Some((k, oracle_len));
        eprintln!(
            "[{profile}_vs_k k={k}] verify={} top_level_whir_proof_count=1 \
             family_columnar_subproof_count={} proof_bytes={} public_statement_bytes={} \
             backend_table_count=1 opened_field_elements={} whir_num_vars={} sumcheck_rounds={} \
             transcript_squeezes={} \
             pcs_merkle_opening_proxy={} ajtai_linear_form_claims={} product_law={:?} \
             beta_action={:?} ring_degree={} ajtai_matrix_vector_evaluator={:?} \
             kappa={} opening_len={} projection_mode={:?} projection_block_len={} \
             range_mode={:?} bound_b={} projection_output_len={} \
             monomial_embedding_enabled={} oracle_len={} monomial_witness_coords={} \
             representative_coords={} range_residual_coords={} constraint_family_count={} \
             manifest_component_count={} manifest_coordinate_count={} \
             source_view_backend_column_count={} \
             source_view_materialized_coordinate_count={} manifest_backend_column_count={} \
             manifest_materialized_coordinate_count={} membership_challenge_count=1 \
             message_round_count={} message_coordinate_count={} \
             message_to_trace_binding_count={} sumcheck_transition_count={}",
            verify_ok,
            proof.family_columnar_subproofs.len(),
            canonical_whir_proof_bytes(&proof).len(),
            public.canonical_bytes().len(),
            proof.private_opening_evals.len(),
            proof.num_vars,
            proof.sumcheck_rounds_4.len(),
            proof.private_opening_evals.len(),
            proof.private_opening_evals.len(),
            decoded_relation
                .ring_module_layout
                .commitment_module_dimension
                * D,
            decoded_relation.algebra_law.product_law,
            decoded_relation.algebra_law.beta_action,
            decoded_relation.algebra_law.ring_degree,
            decoded_relation
                .ajtai_linear_algebra_layout
                .matrix_vector_evaluator,
            decoded_relation.ajtai_linear_algebra_layout.kappa,
            decoded_relation.ajtai_linear_algebra_layout.opening_len,
            decoded_relation
                .ajtai_norm_range_layout
                .projection_layout
                .projection_mode,
            decoded_relation
                .ajtai_norm_range_layout
                .projection_layout
                .block_len,
            decoded_relation.ajtai_norm_range_layout.range_mode,
            decoded_relation.ajtai_norm_range_layout.norm_bound,
            projection_output_len,
            monomial_embedding_enabled,
            oracle_len,
            monomial_witness_coords,
            representative_coords,
            range_residual_coords,
            constraint_family_count,
            manifest_component_count,
            manifest_coordinate_count,
            source_view_backend_column_count,
            source_view_materialized_coordinate_count,
            manifest_backend_column_count,
            manifest_materialized_coordinate_count,
            message_round_count,
            message_coordinate_count,
            message_to_trace_binding_count,
            sumcheck_transition_count,
        );
        eprintln!(
            "[{profile}_vs_k k={k}] source_r1cs_residual_claims={} \
             source_r1cs_residual_verifier_evaluations={} \
             folded_gr1cs_boundary_claims={} folded_gr1cs_product_claims={}",
            source_r1cs_claims,
            verifier_profile.source_r1cs_residual_verifier_evaluations,
            folded_gr1cs_claims,
            folded_gr1cs_product_claims,
        );
        eprintln!(
            "[{profile}_vs_k k={k}] verify_total_ms={:.3} verify_whir_pcs_ms={:.3} \
             verify_merkle_or_pcs_opening_ms={:.3} verify_transcript_ms={:.3} \
             verify_sumcheck_rounds_ms={:.3} verify_final_constraint_eval_ms={:.3} \
             verify_final_eval_manifest_ms={:.3} verify_final_eval_source_r1cs_ms={:.3} \
             verify_final_eval_folded_boundary_ms={:.3} \
             verify_final_eval_product_residual_ms={:.3} \
             verify_final_eval_ajtai_ms={:.3} verify_final_eval_range_ms={:.3} \
             verify_final_eval_message_view_ms={:.3} \
             verify_manifest_membership_eval_ms={:.3} verify_message_view_eval_ms={:.3} \
             verify_projection_eval_ms={:.3} verify_monomial_embedding_eval_ms={:.3} \
             verify_representative_eval_ms={:.3} verify_ajtai_eval_ms={:.3}",
            verifier_profile.verify_total_ms,
            verifier_profile.verify_whir_pcs_ms,
            verifier_profile.verify_merkle_or_pcs_opening_ms,
            verifier_profile.verify_transcript_ms,
            verifier_profile.verify_sumcheck_rounds_ms,
            verifier_profile.verify_final_constraint_eval_ms,
            verifier_profile.verify_final_eval_manifest_ms,
            verifier_profile.verify_final_eval_source_r1cs_ms,
            verifier_profile.verify_final_eval_folded_boundary_ms,
            verifier_profile.verify_final_eval_product_residual_ms,
            verifier_profile.verify_final_eval_ajtai_ms,
            verifier_profile.verify_final_eval_range_ms,
            verifier_profile.verify_final_eval_message_view_ms,
            verifier_profile.verify_manifest_membership_eval_ms,
            verifier_profile.verify_message_view_eval_ms,
            verifier_profile.verify_projection_eval_ms,
            verifier_profile.verify_monomial_embedding_eval_ms,
            verifier_profile.verify_representative_eval_ms,
            verifier_profile.verify_ajtai_eval_ms,
        );
        write_symbt3_scaling_csv_row(&Symbt3ScalingCsvRow {
            profile,
            route_kind: "lower_level_symbt3_development",
            k,
            proof_bytes: canonical_whir_proof_bytes(&proof).len(),
            public_statement_bytes: public.canonical_bytes().len(),
            prove_ms,
            verify_ms,
            whir_num_vars: proof.num_vars,
            oracle_len,
            opened_field_elements: proof.private_opening_evals.len(),
            sumcheck_rounds: proof.sumcheck_rounds_4.len(),
            transcript_squeezes: proof.private_opening_evals.len(),
            pcs_merkle_opening_proxy: proof.private_opening_evals.len(),
            top_level_whir_proof_count: SYMBT3_TOP_LEVEL_WHIR_PROOF_COUNT,
            family_columnar_subproof_count: proof.family_columnar_subproofs.len(),
            backend_table_count: SYMBT3_BACKEND_TABLE_COUNT,
            verify_whir_pcs_ms: verifier_profile.verify_whir_pcs_ms,
            verify_transcript_ms: verifier_profile.verify_transcript_ms,
            verify_sumcheck_rounds_ms: verifier_profile.verify_sumcheck_rounds_ms,
            verify_final_constraint_eval_ms: verifier_profile.verify_final_constraint_eval_ms,
            verify_manifest_membership_eval_ms: verifier_profile.verify_manifest_membership_eval_ms,
            verify_message_view_eval_ms: verifier_profile.verify_message_view_eval_ms,
            verify_projection_eval_ms: verifier_profile.verify_projection_eval_ms,
            verify_monomial_embedding_eval_ms: verifier_profile.verify_monomial_embedding_eval_ms,
            verify_representative_eval_ms: verifier_profile.verify_representative_eval_ms,
            verify_ajtai_eval_ms: verifier_profile.verify_ajtai_eval_ms,
            source_r1cs_residual_claims: source_r1cs_claims,
            source_r1cs_residual_verifier_evaluations: verifier_profile
                .source_r1cs_residual_verifier_evaluations,
            folded_gr1cs_boundary_claims: folded_gr1cs_claims,
            folded_gr1cs_product_claims,
            manifest_public_bytes: decoded_relation
                .batch_manifest_layout
                .digest(decoded_relation.shape.accumulator_shape.digest_scheme)
                .len(),
            manifest_logical_coordinates: manifest_coordinate_count,
            manifest_coordinate_count,
            source_view_backend_column_count,
            source_view_materialized_coordinate_count,
            manifest_backend_column_count,
            manifest_materialized_coordinate_count,
            accumulator_transition_claims: 1,
            message_view_coordinates: message_coordinate_count,
            message_coordinate_count,
            message_to_trace_binding_count,
            verify_final_eval_manifest_ms: verifier_profile.verify_final_eval_manifest_ms,
            verify_final_eval_source_r1cs_ms: verifier_profile.verify_final_eval_source_r1cs_ms,
            verify_final_eval_folded_boundary_ms: verifier_profile
                .verify_final_eval_folded_boundary_ms,
            verify_final_eval_product_residual_ms: verifier_profile
                .verify_final_eval_product_residual_ms,
            verify_final_eval_ajtai_ms: verifier_profile.verify_final_eval_ajtai_ms,
            verify_final_eval_range_ms: verifier_profile.verify_final_eval_range_ms,
            verify_final_eval_message_view_ms: verifier_profile.verify_final_eval_message_view_ms,
            product_route_selected: false,
            monolithic_fallback_used: false,
        });

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new(format!("prove_{profile}"), k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::prove_symbt3_batched_cp(
                        black_box(&pk),
                        black_box(&public),
                        black_box(&witness),
                    )
                    .unwrap_or_else(|| panic!("{profile} proof")),
                );
            });
        });
        group.bench_function(BenchmarkId::new(format!("verify_{profile}"), k), |b| {
            b.iter(|| {
                black_box(
                    <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
                        black_box(&vk),
                        black_box(&public),
                        black_box(&proof),
                    )
                    .unwrap_or(false),
                );
            });
        });
    }

    group.finish();
}

fn symbt3_relation_for_bench_profile(
    mut relation: BatchedCpSymbt3RelationDescription,
    profile: &str,
) -> BatchedCpSymbt3RelationDescription {
    match profile {
        "symbt3_i2" => {
            symbt3_set_projection_profile(
                &mut relation,
                Symbt3ProjectionMode::DirectDevDenseProjectionV1,
                Symbt3RangeMode::DirectSignedRangeDevV1,
            );
        }
        "symbt3_j_projection_only" => {
            symbt3_set_projection_profile(
                &mut relation,
                Symbt3ProjectionMode::StructuredBlockProjectionV1,
                Symbt3RangeMode::DirectSignedRangeDevV1,
            );
        }
        "symbt3_j_monomial_only" => {
            symbt3_set_projection_profile(
                &mut relation,
                Symbt3ProjectionMode::DirectDevDenseProjectionV1,
                Symbt3RangeMode::MonomialEmbeddingRangeV1,
            );
        }
        "symbt3_j" | "symbt3_j_full" => {}
        _ => {}
    }
    relation.message_semantic_layout = Symbt3MessageSemanticLayout::from_shape_and_layouts(
        &relation.shape,
        &relation.oracle_layout,
        &relation.algebra_law,
        &relation.gr1cs_residual_layout,
        &relation.ajtai_linear_algebra_layout,
        &relation.ajtai_norm_range_layout,
        &relation.batch_manifest_layout,
        relation.shape.accumulator_shape.digest_scheme,
    );
    relation
}

fn symbt3_set_projection_profile(
    relation: &mut BatchedCpSymbt3RelationDescription,
    projection_mode: Symbt3ProjectionMode,
    range_mode: Symbt3RangeMode,
) {
    let input_len = relation.ajtai_norm_range_layout.projection_layout.input_len;
    let block_len = match projection_mode {
        Symbt3ProjectionMode::DirectDevDenseProjectionV1 => input_len.max(1),
        Symbt3ProjectionMode::StructuredBlockProjectionV1 => D.min(input_len.max(1)),
    };
    let rows_per_block = 1usize;
    let output_len = match projection_mode {
        Symbt3ProjectionMode::DirectDevDenseProjectionV1 => input_len,
        Symbt3ProjectionMode::StructuredBlockProjectionV1 => {
            input_len.div_ceil(block_len) * rows_per_block
        }
    };
    relation
        .ajtai_norm_range_layout
        .projection_layout
        .projection_mode = projection_mode;
    relation.ajtai_norm_range_layout.projection_layout.block_len = block_len;
    relation
        .ajtai_norm_range_layout
        .projection_layout
        .rows_per_block = rows_per_block;
    relation
        .ajtai_norm_range_layout
        .projection_layout
        .output_len = output_len;
    relation.ajtai_norm_range_layout.range_mode = range_mode;
    relation.ajtai_norm_range_layout.range_layout.range_mode = range_mode;
    match range_mode {
        Symbt3RangeMode::DirectSignedRangeDevV1 => {
            relation.ajtai_norm_range_layout.range_layout.table_digest = None;
            relation
                .ajtai_norm_range_layout
                .range_layout
                .monomial_embedding_layout_digest = None;
        }
        Symbt3RangeMode::MonomialEmbeddingRangeV1 => {
            let scheme = relation.shape.accumulator_shape.digest_scheme;
            relation.ajtai_norm_range_layout.range_layout.table_digest = Some(
                relation
                    .ajtai_norm_range_layout
                    .monomial_embedding_layout
                    .table_polynomial_digest,
            );
            relation
                .ajtai_norm_range_layout
                .range_layout
                .monomial_embedding_layout_digest = Some(
                relation
                    .ajtai_norm_range_layout
                    .monomial_embedding_layout
                    .digest(scheme),
            );
        }
    }
}

fn bench_symbt3_e_vs_k(c: &mut Criterion) {
    bench_symbt3_profile_vs_k(c, "symbt3_e");
}

fn bench_symbt3_f_vs_k(c: &mut Criterion) {
    bench_symbt3_profile_vs_k(c, "symbt3_f");
}

fn bench_symbt3_g_vs_k(c: &mut Criterion) {
    bench_symbt3_profile_vs_k(c, "symbt3_g");
}

fn bench_symbt3_h_vs_k(c: &mut Criterion) {
    bench_symbt3_profile_vs_k(c, "symbt3_h");
}

fn bench_symbt3_i_vs_k(c: &mut Criterion) {
    bench_symbt3_profile_vs_k(c, "symbt3_i");
}

fn bench_symbt3_i2_vs_k(c: &mut Criterion) {
    bench_symbt3_profile_vs_k(c, "symbt3_i2");
}

fn bench_symbt3_j_vs_k(c: &mut Criterion) {
    bench_symbt3_profile_vs_k(c, "symbt3_j");
}

fn bench_symbt3_j_projection_only_vs_k(c: &mut Criterion) {
    bench_symbt3_profile_vs_k(c, "symbt3_j_projection_only");
}

fn bench_symbt3_j_monomial_only_vs_k(c: &mut Criterion) {
    bench_symbt3_profile_vs_k(c, "symbt3_j_monomial_only");
}

fn bench_symbt3_j_full_vs_k(c: &mut Criterion) {
    bench_symbt3_profile_vs_k(c, "symbt3_j_full");
}

fn bench_verify_symbt3_research_authority_candidate(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/symbt3_research_vs_product_verify_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/symbt3_research_vs_product_verify_vs_k");
    configure_pipeline_group(&mut group);

    let ks = public_verify_ks();
    eprintln!(
        "[symbt3_research_vs_product_verify_vs_k] k_values={ks:?} non_zk_research_only=true product_routing_changed=false"
    );

    for &k in &ks {
        let fixture = public_whir_fixture(k);
        let product_verify_ok =
            fixture
                .verifier
                .verify_public(&fixture.public_inputs, &fixture.proof, &fixture.r1cs);
        assert!(
            product_verify_ok,
            "product verify_public baseline must verify for k={k}"
        );

        let bucket = batched_cp_bucket_from_fixture(&fixture, k);
        let descriptor = BatchedCpSymbt3SetupDescriptor::new(
            bucket.shape.clone(),
            &fixture.ajtai,
            &fixture.r1cs,
            fixture.input_bound,
        );
        let symbt3_relation = <WhirSnark as CpBackend>::symbt3_relation_description(&descriptor)
            .expect("WHIR exposes SYMBT3 research relation");
        let decoded_relation = BatchedCpSymbt3RelationDescription::from_context_bytes(
            symbt3_relation.context.as_ref().expect("SYMBT3 context"),
        )
        .expect("SYMBT3 context decodes");
        assert!(
            decoded_relation.has_symbt3_j_families(),
            "research authority candidate requires the cumulative J2 family set"
        );
        let (symbt3_pk, symbt3_vk) = <WhirSnark as CpBackend>::setup(&symbt3_relation);
        let symbt3_public = bucket.symbt3_public_statement_for_relation(&decoded_relation);
        let symbt3_witness = bucket.symbt3_witness_for_relation(&decoded_relation);
        let symbt3_proof = <WhirSnark as CpBackend>::prove_symbt3_batched_cp(
            &symbt3_pk,
            &symbt3_public,
            &symbt3_witness,
        )
        .expect("SYMBT3 research proof");
        let research_profile = Symbt3AuthorityProfile::research_authority_candidate_from_relation(
            &decoded_relation,
            64,
        );
        let product_profile =
            Symbt3AuthorityProfile::authority_candidate_from_relation(&decoded_relation, 128);
        let research_verify_ok = WhirSnark::verify_symbt3_research_authority_candidate(
            &symbt3_vk,
            &symbt3_public,
            &symbt3_proof,
            &research_profile,
        )
        .unwrap_or(false);
        let product_authority_ok = WhirSnark::verify_symbt3_authority_profile(
            &symbt3_vk,
            &symbt3_public,
            &symbt3_proof,
            &product_profile,
        )
        .unwrap_or(false);
        assert!(
            research_verify_ok,
            "SYMBT3 research authority candidate must verify for k={k}"
        );
        assert!(
            !product_authority_ok,
            "SYMBT3 research candidate must not pass ProductAuthority for k={k}"
        );

        let (_, symbt3_cost) = WhirSnark::profile_symbt3_batched_cp_verifier(
            &symbt3_vk,
            &symbt3_public,
            &symbt3_proof,
        )
        .expect("SYMBT3 research verifier profile");
        eprintln!(
            "[symbt3_research_vs_product_verify_vs_k k={k}] \
             product_verify_public_ok={} symbt3_research_ok={} symbt3_product_authority_ok={} \
             product_public_envelope_bytes={} symbt3_proof_bytes={} \
             symbt3_public_statement_bytes={} top_level_whir_proof_count=1 \
             family_columnar_subproof_count={} backend_table_count=1 \
             symbt3_num_vars={} symbt3_opened_field_elements={} \
             symbt3_verify_total_ms={:.3} symbt3_verify_whir_pcs_ms={:.3} \
             symbt3_verify_transcript_ms={:.3} symbt3_verify_final_constraint_eval_ms={:.3} \
             symbt3_verify_final_eval_manifest_ms={:.3} \
             symbt3_verify_final_eval_source_r1cs_ms={:.3} \
             symbt3_verify_final_eval_folded_boundary_ms={:.3} \
             symbt3_verify_final_eval_product_residual_ms={:.3} \
             symbt3_verify_final_eval_ajtai_ms={:.3} \
             symbt3_verify_final_eval_range_ms={:.3} \
             symbt3_verify_final_eval_message_view_ms={:.3} \
             non_zk_research_only=true product_routing_changed=false",
            product_verify_ok,
            research_verify_ok,
            product_authority_ok,
            fixture.profile.public_envelope_bytes,
            canonical_whir_proof_bytes(&symbt3_proof).len(),
            symbt3_public.canonical_bytes().len(),
            symbt3_proof.family_columnar_subproofs.len(),
            symbt3_proof.num_vars,
            symbt3_proof.private_opening_evals.len(),
            symbt3_cost.verify_total_ms,
            symbt3_cost.verify_whir_pcs_ms,
            symbt3_cost.verify_transcript_ms,
            symbt3_cost.verify_final_constraint_eval_ms,
            symbt3_cost.verify_final_eval_manifest_ms,
            symbt3_cost.verify_final_eval_source_r1cs_ms,
            symbt3_cost.verify_final_eval_folded_boundary_ms,
            symbt3_cost.verify_final_eval_product_residual_ms,
            symbt3_cost.verify_final_eval_ajtai_ms,
            symbt3_cost.verify_final_eval_range_ms,
            symbt3_cost.verify_final_eval_message_view_ms,
        );

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("verify_public_product", k), |b| {
            b.iter(|| {
                black_box(fixture.verifier.verify_public(
                    black_box(&fixture.public_inputs),
                    black_box(&fixture.proof),
                    black_box(&fixture.r1cs),
                ));
            });
        });
        group.bench_function(
            BenchmarkId::new("verify_symbt3_research_authority_candidate", k),
            |b| {
                b.iter(|| {
                    black_box(
                        WhirSnark::verify_symbt3_research_authority_candidate(
                            black_box(&symbt3_vk),
                            black_box(&symbt3_public),
                            black_box(&symbt3_proof),
                            black_box(&research_profile),
                        )
                        .unwrap_or(false),
                    );
                });
            },
        );
    }

    group.finish();
}

fn bench_symbt3_accumulator_research_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/symbt3_accumulator_research_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/symbt3_accumulator_research_vs_k");
    configure_pipeline_group(&mut group);

    let ks = public_verify_ks();
    let base_fixture = public_whir_fixture(1);
    eprintln!(
        "[symbt3_accumulator_research_vs_k] k_values={ks:?} non_zk_research_only=true product_routing_changed=false"
    );

    for &k in &ks {
        let bucket = batched_cp_bucket_from_fixture(&base_fixture, k);
        let descriptor = BatchedCpSymbt3SetupDescriptor::new(
            bucket.shape.clone(),
            &base_fixture.ajtai,
            &base_fixture.r1cs,
            base_fixture.input_bound,
        );
        let relation = <WhirSnark as CpBackend>::symbt3_relation_description(&descriptor)
            .expect("WHIR exposes SYMBT3 accumulator relation");
        let decoded_relation = BatchedCpSymbt3RelationDescription::from_context_bytes(
            relation.context.as_ref().expect("SYMBT3 context"),
        )
        .expect("SYMBT3 context decodes");
        let decoded_relation = symbt3_relation_for_bench_profile(decoded_relation, "symbt3_j");
        let relation = decoded_relation.to_relation_description();
        let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
        let public = bucket.symbt3_public_statement_for_relation(&decoded_relation);
        let witness = bucket.symbt3_witness_for_relation(&decoded_relation);
        let profile =
            Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
                &decoded_relation,
                64,
            );
        let profile_digest = profile.digest(decoded_relation.shape.accumulator_shape.digest_scheme);
        let accumulator_instance = Symbt3AccumulatorInstance::from_public_statement_with_scheme(
            bucket.shape.accumulator_shape.digest_scheme,
            profile_digest,
            public.old_accumulator_digest,
            public.new_accumulator_digest,
            &public,
        );
        let accumulator_witness =
            Symbt3AccumulatorWitness::from_symbt3_witness(&decoded_relation, &witness);
        let prove_start = std::time::Instant::now();
        let proof = WhirSnark::prove_public_symbt3_accumulator_research_non_zk(
            &pk,
            &profile,
            &accumulator_instance,
            &accumulator_witness,
        )
        .unwrap_or_else(|| panic!("K4 SYMBT3 accumulator research proof for k={k}"));
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;
        let verify_start = std::time::Instant::now();
        let verify_ok = WhirSnark::verify_public_symbt3_accumulator_research_non_zk(
            &vk,
            &profile,
            &accumulator_instance,
            &proof,
        );
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;
        assert!(
            verify_ok,
            "K4 SYMBT3 accumulator research proof must verify for k={k}"
        );
        assert_eq!(proof.family_columnar_subproofs.len(), 0);
        assert_eq!(
            decoded_relation
                .message_semantic_layout
                .message_to_trace_binding_count(),
            0
        );

        let (_, verifier_profile) =
            WhirSnark::profile_symbt3_batched_cp_verifier(&vk, &public, &proof)
                .expect("K4 SYMBT3 verifier profile");
        let source_r1cs_claims = public.source_assignment_roots.len()
            * decoded_relation.r1cs_evaluator_layout.num_constraints
            * D;
        let folded_gr1cs_claims = decoded_relation
            .gr1cs_residual_layout
            .folded_evaluation_coordinate_count;
        let folded_gr1cs_product_claims = decoded_relation
            .gr1cs_residual_layout
            .folded_evaluation_coordinate_count
            / 3;
        let manifest_logical_coordinates = decoded_relation
            .batch_manifest_layout
            .source_column_layout
            .coordinate_count
            * public.active_count;
        let source_view_backend_column_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
        let source_view_materialized_coordinate_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
        let manifest_backend_column_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
        let manifest_materialized_coordinate_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
        let message_view_coordinates = decoded_relation
            .message_semantic_layout
            .view_coordinate_count(public.active_count);
        let message_to_trace_binding_count = decoded_relation
            .message_semantic_layout
            .message_to_trace_binding_count();
        let oracle_len = 1usize << proof.num_vars;
        let proof_bytes = canonical_whir_proof_bytes(&proof).len();
        let public_statement_bytes = accumulator_instance.canonical_bytes().len();
        let manifest_public_bytes = public.batch_manifest_root.len()
            + public.manifest_oracle_root.len()
            + public.batch_manifest_layout_digest.len();

        eprintln!(
            "[symbt3_accumulator_research_vs_k k={k}] verify={} profile=K4_NonZK_research \
             proof_bytes={} public_statement_bytes={} prove_ms={:.3} verify_ms={:.3} \
             whir_num_vars={} oracle_len={} opened_field_elements={} sumcheck_rounds={} \
             transcript_squeezes={} pcs_merkle_opening_proxy={} top_level_whir_proof_count=1 \
             family_columnar_subproof_count={} backend_table_count=1 \
             message_to_trace_binding_count={} accumulator_transition_claims=1 \
             source_view_backend_column_count={} source_view_materialized_coordinate_count={} \
             manifest_backend_column_count={} manifest_materialized_coordinate_count={} \
             manifest_public_bytes={} manifest_logical_coordinates={} \
             message_view_coordinates={} source_r1cs_residual_claims={} \
             source_r1cs_residual_verifier_evaluations={} \
             verify_whir_pcs_ms={:.3} verify_transcript_ms={:.3} \
             verify_final_constraint_eval_ms={:.3} product_routing_changed=false",
            verify_ok,
            proof_bytes,
            public_statement_bytes,
            prove_ms,
            verify_ms,
            proof.num_vars,
            oracle_len,
            proof.private_opening_evals.len(),
            proof.sumcheck_rounds_4.len(),
            proof.private_opening_evals.len(),
            proof.private_opening_evals.len(),
            proof.family_columnar_subproofs.len(),
            message_to_trace_binding_count,
            source_view_backend_column_count,
            source_view_materialized_coordinate_count,
            manifest_backend_column_count,
            manifest_materialized_coordinate_count,
            manifest_public_bytes,
            manifest_logical_coordinates,
            message_view_coordinates,
            source_r1cs_claims,
            verifier_profile.source_r1cs_residual_verifier_evaluations,
            verifier_profile.verify_whir_pcs_ms,
            verifier_profile.verify_transcript_ms,
            verifier_profile.verify_final_constraint_eval_ms,
        );

        write_symbt3_scaling_csv_row(&Symbt3ScalingCsvRow {
            profile: "symbt3_accumulator_research",
            route_kind: "symbt3_accumulator_research_non_zk",
            k,
            proof_bytes,
            public_statement_bytes,
            prove_ms,
            verify_ms,
            whir_num_vars: proof.num_vars,
            oracle_len,
            opened_field_elements: proof.private_opening_evals.len(),
            sumcheck_rounds: proof.sumcheck_rounds_4.len(),
            transcript_squeezes: proof.private_opening_evals.len(),
            pcs_merkle_opening_proxy: proof.private_opening_evals.len(),
            top_level_whir_proof_count: SYMBT3_TOP_LEVEL_WHIR_PROOF_COUNT,
            family_columnar_subproof_count: proof.family_columnar_subproofs.len(),
            backend_table_count: SYMBT3_BACKEND_TABLE_COUNT,
            verify_whir_pcs_ms: verifier_profile.verify_whir_pcs_ms,
            verify_transcript_ms: verifier_profile.verify_transcript_ms,
            verify_sumcheck_rounds_ms: verifier_profile.verify_sumcheck_rounds_ms,
            verify_final_constraint_eval_ms: verifier_profile.verify_final_constraint_eval_ms,
            verify_manifest_membership_eval_ms: verifier_profile.verify_manifest_membership_eval_ms,
            verify_message_view_eval_ms: verifier_profile.verify_message_view_eval_ms,
            verify_projection_eval_ms: verifier_profile.verify_projection_eval_ms,
            verify_monomial_embedding_eval_ms: verifier_profile.verify_monomial_embedding_eval_ms,
            verify_representative_eval_ms: verifier_profile.verify_representative_eval_ms,
            verify_ajtai_eval_ms: verifier_profile.verify_ajtai_eval_ms,
            source_r1cs_residual_claims: source_r1cs_claims,
            source_r1cs_residual_verifier_evaluations: verifier_profile
                .source_r1cs_residual_verifier_evaluations,
            folded_gr1cs_boundary_claims: folded_gr1cs_claims,
            folded_gr1cs_product_claims,
            manifest_public_bytes,
            manifest_logical_coordinates,
            manifest_coordinate_count: manifest_logical_coordinates,
            source_view_backend_column_count,
            source_view_materialized_coordinate_count,
            manifest_backend_column_count,
            manifest_materialized_coordinate_count,
            accumulator_transition_claims: 1,
            message_view_coordinates,
            message_coordinate_count: message_view_coordinates,
            message_to_trace_binding_count,
            verify_final_eval_manifest_ms: verifier_profile.verify_final_eval_manifest_ms,
            verify_final_eval_source_r1cs_ms: verifier_profile.verify_final_eval_source_r1cs_ms,
            verify_final_eval_folded_boundary_ms: verifier_profile
                .verify_final_eval_folded_boundary_ms,
            verify_final_eval_product_residual_ms: verifier_profile
                .verify_final_eval_product_residual_ms,
            verify_final_eval_ajtai_ms: verifier_profile.verify_final_eval_ajtai_ms,
            verify_final_eval_range_ms: verifier_profile.verify_final_eval_range_ms,
            verify_final_eval_message_view_ms: verifier_profile.verify_final_eval_message_view_ms,
            product_route_selected: false,
            monolithic_fallback_used: false,
        });

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(
            BenchmarkId::new("prove_public_symbt3_accumulator_research_non_zk", k),
            |b| {
                b.iter(|| {
                    black_box(
                        WhirSnark::prove_public_symbt3_accumulator_research_non_zk(
                            black_box(&pk),
                            black_box(&profile),
                            black_box(&accumulator_instance),
                            black_box(&accumulator_witness),
                        )
                        .expect("K4 SYMBT3 accumulator research proof"),
                    );
                });
            },
        );
        group.bench_function(
            BenchmarkId::new("verify_public_symbt3_accumulator_research_non_zk", k),
            |b| {
                b.iter(|| {
                    black_box(WhirSnark::verify_public_symbt3_accumulator_research_non_zk(
                        black_box(&vk),
                        black_box(&profile),
                        black_box(&accumulator_instance),
                        black_box(&proof),
                    ));
                });
            },
        );
    }

    group.finish();
}

struct MonolithicProductRouteMeasurement {
    fixture: PublicWhirBenchFixture,
    verify_ms: f64,
    proof_bytes: usize,
    public_statement_bytes: usize,
}

fn monolithic_product_route_measurement(k: usize) -> MonolithicProductRouteMeasurement {
    let fixture = public_whir_fixture(k);
    let verify_start = std::time::Instant::now();
    let verify_ok =
        fixture
            .verifier
            .verify_public(&fixture.public_inputs, &fixture.proof, &fixture.r1cs);
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        verify_ok,
        "monolithic typed CP product proof must verify for k={k}"
    );

    let proof_bytes = fixture.profile.cp_proof_bytes + fixture.profile.output_proof_bytes;
    let public_statement_bytes = fixture
        .proof
        .canonical_compressed_public_envelope_bytes(
            <WhirSnark as BackendSnark>::public_digest_scheme(),
            &fixture.public_inputs,
            &fixture.r1cs,
            &[],
            &[],
        )
        .len();

    MonolithicProductRouteMeasurement {
        fixture,
        verify_ms,
        proof_bytes,
        public_statement_bytes,
    }
}

struct Symbt3AuthorityRouteMeasurement {
    pk: WhirProvingKey,
    vk: WhirVerifyingKey,
    profile: Symbt3AuthorityProfile,
    accumulator_instance: Symbt3AccumulatorInstance,
    accumulator_witness: Symbt3AccumulatorWitness,
    csv: Symbt3ScalingCsvRow<'static>,
    proof: WhirProof,
}

fn symbt3_authority_route_measurement(
    base_fixture: &PublicWhirBenchFixture,
    k: usize,
) -> Symbt3AuthorityRouteMeasurement {
    let bucket = batched_cp_bucket_from_fixture(base_fixture, k);
    let descriptor = BatchedCpSymbt3SetupDescriptor::new(
        bucket.shape.clone(),
        &base_fixture.ajtai,
        &base_fixture.r1cs,
        base_fixture.input_bound,
    );
    let relation = <WhirSnark as CpBackend>::symbt3_relation_description(&descriptor)
        .expect("WHIR exposes SYMBT3 accumulator relation");
    let decoded_relation = BatchedCpSymbt3RelationDescription::from_context_bytes(
        relation.context.as_ref().expect("SYMBT3 context"),
    )
    .expect("SYMBT3 context decodes");
    let decoded_relation = symbt3_relation_for_bench_profile(decoded_relation, "symbt3_j");
    let relation = decoded_relation.to_relation_description();
    let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
    let public = bucket.symbt3_public_statement_for_relation(&decoded_relation);
    let witness = bucket.symbt3_witness_for_relation(&decoded_relation);
    let profile =
        Symbt3AuthorityProfile::accumulator_non_zk_integrity_product_authority_from_relation(
            &decoded_relation,
            64,
        );
    let profile_digest = profile.digest(decoded_relation.shape.accumulator_shape.digest_scheme);
    let accumulator_instance = Symbt3AccumulatorInstance::from_public_statement_with_scheme(
        bucket.shape.accumulator_shape.digest_scheme,
        profile_digest,
        public.old_accumulator_digest,
        public.new_accumulator_digest,
        &public,
    );
    let accumulator_witness =
        Symbt3AccumulatorWitness::from_symbt3_witness(&decoded_relation, &witness);
    let prove_start = std::time::Instant::now();
    let proof = WhirSnark::prove_public_symbt3_accumulator_non_zk_integrity(
        &pk,
        &profile,
        &accumulator_instance,
        &accumulator_witness,
    )
    .unwrap_or_else(|| panic!("K6a SYMBT3 accumulator authority proof for k={k}"));
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;
    let verify_start = std::time::Instant::now();
    let verify_ok = WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
        &vk,
        &profile,
        &accumulator_instance,
        ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
        &proof,
    );
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        verify_ok,
        "K6a SYMBT3 accumulator authority proof must verify for k={k}"
    );
    assert_eq!(proof.family_columnar_subproofs.len(), 0);
    assert_eq!(
        decoded_relation
            .message_semantic_layout
            .message_to_trace_binding_count(),
        0
    );

    let (_, verifier_profile) = WhirSnark::profile_symbt3_batched_cp_verifier(&vk, &public, &proof)
        .expect("K6a SYMBT3 verifier profile");
    let source_r1cs_claims = public.source_assignment_roots.len()
        * decoded_relation.r1cs_evaluator_layout.num_constraints
        * D;
    let folded_gr1cs_claims = decoded_relation
        .gr1cs_residual_layout
        .folded_evaluation_coordinate_count;
    let folded_gr1cs_product_claims = decoded_relation
        .gr1cs_residual_layout
        .folded_evaluation_coordinate_count
        / 3;
    let manifest_logical_coordinates = decoded_relation
        .batch_manifest_layout
        .source_column_layout
        .coordinate_count
        * public.active_count;
    let source_view_backend_column_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
    let source_view_materialized_coordinate_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
    let manifest_backend_column_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
    let manifest_materialized_coordinate_count = SYMBT3_DIAGNOSTIC_MATERIALIZED_COUNTER;
    let message_view_coordinates = decoded_relation
        .message_semantic_layout
        .view_coordinate_count(public.active_count);
    let message_to_trace_binding_count = decoded_relation
        .message_semantic_layout
        .message_to_trace_binding_count();
    let oracle_len = 1usize << proof.num_vars;
    let proof_bytes = canonical_whir_proof_bytes(&proof).len();
    let public_statement_bytes = accumulator_instance.canonical_bytes().len();
    let manifest_public_bytes = public.batch_manifest_root.len()
        + public.manifest_oracle_root.len()
        + public.batch_manifest_layout_digest.len();

    Symbt3AuthorityRouteMeasurement {
        pk,
        vk,
        profile,
        accumulator_instance,
        accumulator_witness,
        csv: Symbt3ScalingCsvRow {
            profile: "symbt3_accumulator_authority",
            route_kind: "symbt3_non_zk_integrity_product",
            k,
            proof_bytes,
            public_statement_bytes,
            prove_ms,
            verify_ms,
            whir_num_vars: proof.num_vars,
            oracle_len,
            opened_field_elements: proof.private_opening_evals.len(),
            sumcheck_rounds: proof.sumcheck_rounds_4.len(),
            transcript_squeezes: proof.private_opening_evals.len(),
            pcs_merkle_opening_proxy: proof.private_opening_evals.len(),
            top_level_whir_proof_count: SYMBT3_TOP_LEVEL_WHIR_PROOF_COUNT,
            family_columnar_subproof_count: proof.family_columnar_subproofs.len(),
            backend_table_count: SYMBT3_BACKEND_TABLE_COUNT,
            verify_whir_pcs_ms: verifier_profile.verify_whir_pcs_ms,
            verify_transcript_ms: verifier_profile.verify_transcript_ms,
            verify_sumcheck_rounds_ms: verifier_profile.verify_sumcheck_rounds_ms,
            verify_final_constraint_eval_ms: verifier_profile.verify_final_constraint_eval_ms,
            verify_manifest_membership_eval_ms: verifier_profile.verify_manifest_membership_eval_ms,
            verify_message_view_eval_ms: verifier_profile.verify_message_view_eval_ms,
            verify_projection_eval_ms: verifier_profile.verify_projection_eval_ms,
            verify_monomial_embedding_eval_ms: verifier_profile.verify_monomial_embedding_eval_ms,
            verify_representative_eval_ms: verifier_profile.verify_representative_eval_ms,
            verify_ajtai_eval_ms: verifier_profile.verify_ajtai_eval_ms,
            source_r1cs_residual_claims: source_r1cs_claims,
            source_r1cs_residual_verifier_evaluations: verifier_profile
                .source_r1cs_residual_verifier_evaluations,
            folded_gr1cs_boundary_claims: folded_gr1cs_claims,
            folded_gr1cs_product_claims,
            manifest_public_bytes,
            manifest_logical_coordinates,
            manifest_coordinate_count: manifest_logical_coordinates,
            source_view_backend_column_count,
            source_view_materialized_coordinate_count,
            manifest_backend_column_count,
            manifest_materialized_coordinate_count,
            accumulator_transition_claims: 1,
            message_view_coordinates,
            message_coordinate_count: message_view_coordinates,
            message_to_trace_binding_count,
            verify_final_eval_manifest_ms: verifier_profile.verify_final_eval_manifest_ms,
            verify_final_eval_source_r1cs_ms: verifier_profile.verify_final_eval_source_r1cs_ms,
            verify_final_eval_folded_boundary_ms: verifier_profile
                .verify_final_eval_folded_boundary_ms,
            verify_final_eval_product_residual_ms: verifier_profile
                .verify_final_eval_product_residual_ms,
            verify_final_eval_ajtai_ms: verifier_profile.verify_final_eval_ajtai_ms,
            verify_final_eval_range_ms: verifier_profile.verify_final_eval_range_ms,
            verify_final_eval_message_view_ms: verifier_profile.verify_final_eval_message_view_ms,
            product_route_selected: true,
            monolithic_fallback_used: false,
        },
        proof,
    }
}

fn bench_symbt3_accumulator_authority_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/symbt3_accumulator_authority_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/symbt3_accumulator_authority_vs_k");
    configure_pipeline_group(&mut group);

    let ks = public_verify_ks();
    let base_fixture = public_whir_fixture(1);
    eprintln!(
        "[symbt3_accumulator_authority_vs_k] k_values={ks:?} non_zk_integrity_product_opt_in=true monolithic_fallback_used=false"
    );

    for &k in &ks {
        let measurement = symbt3_authority_route_measurement(&base_fixture, k);
        let row = &measurement.csv;
        eprintln!(
            "[symbt3_accumulator_authority_vs_k k={k}] verify={} profile=K6a_NonZK_integrity_product \
             route_kind=Symbt3AccumulatorNonZkIntegrity product_route_selected=true \
             monolithic_fallback_used=false proof_bytes={} public_statement_bytes={} \
             prove_ms={:.3} verify_ms={:.3} whir_num_vars={} oracle_len={} \
             opened_field_elements={} sumcheck_rounds={} transcript_squeezes={} \
             pcs_merkle_opening_proxy={} top_level_whir_proof_count=1 \
             family_columnar_subproof_count={} backend_table_count=1 \
             message_to_trace_binding_count={} accumulator_transition_claims=1 \
             source_view_backend_column_count={} source_view_materialized_coordinate_count={} \
             manifest_backend_column_count={} manifest_materialized_coordinate_count={} \
             source_r1cs_residual_claims={} source_r1cs_residual_verifier_evaluations={} \
             verify_whir_pcs_ms={:.3} verify_transcript_ms={:.3} \
             verify_final_constraint_eval_ms={:.3}",
            true,
            row.proof_bytes,
            row.public_statement_bytes,
            row.prove_ms,
            row.verify_ms,
            row.whir_num_vars,
            row.oracle_len,
            row.opened_field_elements,
            row.sumcheck_rounds,
            row.transcript_squeezes,
            row.pcs_merkle_opening_proxy,
            row.family_columnar_subproof_count,
            row.message_to_trace_binding_count,
            row.source_view_backend_column_count,
            row.source_view_materialized_coordinate_count,
            row.manifest_backend_column_count,
            row.manifest_materialized_coordinate_count,
            row.source_r1cs_residual_claims,
            row.source_r1cs_residual_verifier_evaluations,
            row.verify_whir_pcs_ms,
            row.verify_transcript_ms,
            row.verify_final_constraint_eval_ms,
        );

        write_symbt3_scaling_csv_row(row);

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(
            BenchmarkId::new("prove_public_symbt3_accumulator_non_zk_integrity", k),
            |b| {
                b.iter(|| {
                    black_box(
                        WhirSnark::prove_public_symbt3_accumulator_non_zk_integrity(
                            black_box(&measurement.pk),
                            black_box(&measurement.profile),
                            black_box(&measurement.accumulator_instance),
                            black_box(&measurement.accumulator_witness),
                        )
                        .expect("K6a SYMBT3 accumulator authority proof"),
                    );
                });
            },
        );
        group.bench_function(
            BenchmarkId::new("verify_public_symbt3_accumulator_non_zk_integrity", k),
            |b| {
                b.iter(|| {
                    black_box(
                        WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
                            black_box(&measurement.vk),
                            black_box(&measurement.profile),
                            black_box(&measurement.accumulator_instance),
                            black_box(ProductProofKind::Symbt3AccumulatorNonZkIntegrity),
                            black_box(&measurement.proof),
                        ),
                    );
                });
            },
        );
    }

    group.finish();
}

fn bench_product_route_comparison_vs_k(c: &mut Criterion) {
    if !criterion_filter_allows("whir_scaling/product_route_comparison_vs_k") {
        return;
    }

    let mut group = c.benchmark_group("whir_scaling/product_route_comparison_vs_k");
    configure_reporter_group(&mut group);

    let ks = product_route_comparison_ks();
    let symbt3_base_fixture = public_whir_fixture(1);
    eprintln!(
        "[product_route_comparison_vs_k] k_values={ks:?} monolithic=current_product_authoritative_typed_cp symbt3=explicit_opt_in_non_zk_integrity not_default_product_route=true"
    );

    for &k in &ks {
        let monolithic = monolithic_product_route_measurement(k);
        let symbt3 = symbt3_authority_route_measurement(&symbt3_base_fixture, k);
        let row = ProductRouteComparisonCsvRow {
            k,
            monolithic_verify_ms: monolithic.verify_ms,
            symbt3_verify_ms: symbt3.csv.verify_ms,
            monolithic_prove_ms: monolithic.fixture.prove_ms,
            symbt3_prove_ms: symbt3.csv.prove_ms,
            monolithic_proof_bytes: monolithic.proof_bytes,
            symbt3_proof_bytes: symbt3.csv.proof_bytes,
            monolithic_public_statement_bytes: monolithic.public_statement_bytes,
            symbt3_public_statement_bytes: symbt3.csv.public_statement_bytes,
            symbt3_whir_num_vars: symbt3.csv.whir_num_vars,
            symbt3_oracle_len: symbt3.csv.oracle_len,
            symbt3_opened_field_elements: symbt3.csv.opened_field_elements,
            symbt3_top_level_whir_proof_count: symbt3.csv.top_level_whir_proof_count,
            symbt3_family_columnar_subproof_count: symbt3.csv.family_columnar_subproof_count,
            symbt3_backend_table_count: symbt3.csv.backend_table_count,
            symbt3_accumulator_transition_claims: symbt3.csv.accumulator_transition_claims,
            symbt3_source_r1cs_residual_verifier_evaluations: symbt3
                .csv
                .source_r1cs_residual_verifier_evaluations,
            symbt3_product_route_selected: symbt3.csv.product_route_selected,
            symbt3_monolithic_fallback_used: symbt3.csv.monolithic_fallback_used,
        };
        eprintln!(
            "[product_route_comparison_vs_k k={k}] monolithic_verify_ms={:.3} \
             symbt3_verify_ms={:.3} verify_speedup={:.3} monolithic_proof_bytes={} \
             symbt3_proof_bytes={} proof_size_ratio={:.3} \
             monolithic_public_statement_bytes={} symbt3_public_statement_bytes={} \
             public_size_ratio={:.3} symbt3_product_route_selected={} \
             symbt3_monolithic_fallback_used={}",
            row.monolithic_verify_ms,
            row.symbt3_verify_ms,
            ratio(row.monolithic_verify_ms, row.symbt3_verify_ms),
            row.monolithic_proof_bytes,
            row.symbt3_proof_bytes,
            ratio(
                row.symbt3_proof_bytes as f64,
                row.monolithic_proof_bytes as f64
            ),
            row.monolithic_public_statement_bytes,
            row.symbt3_public_statement_bytes,
            ratio(
                row.symbt3_public_statement_bytes as f64,
                row.monolithic_public_statement_bytes as f64
            ),
            row.symbt3_product_route_selected,
            row.symbt3_monolithic_fallback_used,
        );
        write_product_route_comparison_csv_row(&row);

        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(BenchmarkId::new("emit_joined_csv_row", k), |b| {
            b.iter(|| {
                black_box((
                    row.k,
                    row.monolithic_verify_ms,
                    row.symbt3_verify_ms,
                    row.symbt3_product_route_selected,
                    row.symbt3_monolithic_fallback_used,
                ));
            });
        });
    }

    group.finish();
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
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
    bench_batched_cp_shape_profile_vs_k,
    bench_batched_cp_verify_only_vs_k,
    bench_batched_cp_product_oracle_whir_vs_k,
    bench_batched_cp_semantic_whir_v2_vs_k,
    bench_batched_cp_semantic_columnar_v2_vs_k,
    bench_batched_cp_semantic_columnar_poseidon_v2_vs_k,
    bench_batched_cp_semantic_family_columnar_v2_vs_k,
    bench_batched_cp_semantic_family_columnar_poseidon_v2_vs_k,
    bench_symbt3_e_vs_k,
    bench_symbt3_f_vs_k,
    bench_symbt3_g_vs_k,
    bench_symbt3_h_vs_k,
    bench_symbt3_i_vs_k,
    bench_symbt3_i2_vs_k,
    bench_symbt3_j_vs_k,
    bench_symbt3_j_projection_only_vs_k,
    bench_symbt3_j_monomial_only_vs_k,
    bench_symbt3_j_full_vs_k,
    bench_verify_symbt3_research_authority_candidate,
    bench_symbt3_accumulator_research_vs_k,
    bench_symbt3_accumulator_authority_vs_k,
    bench_product_route_comparison_vs_k,
    bench_public_proof_batched_cp_size_vs_k,
);
criterion_main!(benches);
