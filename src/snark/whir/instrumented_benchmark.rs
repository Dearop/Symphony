//! SYMBT3 instrumented benchmark JSONL contract helpers.
//!
//! This module is benchmark instrumentation only. It does not define or alter
//! WHIR proof payload bytes, public proof envelopes, product routing, or SYMBT3
//! verifier semantics.

use serde_json::{Map, Number, Value};

pub const SYMBT3_INSTRUMENTED_BENCHMARK_JSON_SCHEMA: &str =
    "symphony.symbt3.instrumented_benchmark.v1";

pub const SYMBT3_INSTRUMENTED_BENCHMARK_REQUIRED_TOP_LEVEL_FIELDS: &[&str] = &[
    "schema",
    "k_table",
    "prove_ms",
    "verify_ms",
    "proof_bytes",
    "public_bytes",
    "proof_bytes_by_section",
    "public_bytes_by_section",
    "counters",
    "verifier_timers",
    "prover_timers",
];

pub const SYMBT3_INSTRUMENTED_BENCHMARK_PROOF_SECTION_NAMES: &[&str] = &[
    "header",
    "sumcheck_rounds_3",
    "sumcheck_rounds_4",
    "evaluations_and_z_eval",
    "linear_checks",
    "private_opening_evals",
    "family_columnar_subproofs",
    "whir_pcs_json",
];

pub const SYMBT3_INSTRUMENTED_BENCHMARK_PUBLIC_SECTION_NAMES: &[&str] = &[
    "domain",
    "profile_and_shape",
    "accumulator_boundary",
    "manifest_and_layouts",
    "batch_source_message_digests",
    "folded_values",
    "relation_and_output_digests",
    "other",
];

pub const SYMBT3_INSTRUMENTED_BENCHMARK_COUNTER_NAMES: &[&str] = &[
    "num_oracles",
    "num_roots",
    "num_query_positions",
    "num_merkle_paths",
    "num_hashes_estimate",
    "num_field_ops_estimate",
    "num_extension_field_ops_estimate",
    "peak_alloc_bytes",
    "top_level_whir_proof_count",
    "family_columnar_subproof_count",
    "backend_table_count",
    "source_r1cs_residual_verifier_evaluations",
];

pub const SYMBT3_INSTRUMENTED_BENCHMARK_VERIFIER_TIMER_NAMES: &[&str] = &[
    "transcript_absorb_squeeze",
    "merkle_root_path_verification",
    "field_operations",
    "field_extension_operations",
    "fold_query_evaluation",
    "eq_lagrange_evaluation",
    "constraint_batching",
    "symphony_accumulator_decoding",
    "proof_deserialization",
    "public_input_parsing",
];

pub const SYMBT3_INSTRUMENTED_BENCHMARK_PROVER_TIMER_NAMES: &[&str] = &[
    "oracle_construction",
    "whir_folding_layers",
    "merkle_tree_build",
    "merkle_path_materialization",
    "constraint_construction",
    "constraint_batching",
    "transcript_absorb_squeeze",
    "field_operations",
    "field_extension_operations",
    "allocations_copies",
    "proof_serialization",
    "symphony_accumulator_glue",
];

#[doc(hidden)]
pub struct Symbt3InstrumentedBenchmarkJsonRow<'a> {
    pub profile: &'a str,
    pub route_kind: &'a str,
    pub k_table: usize,
    pub prove_ms: f64,
    pub verify_ms: f64,
    pub proof_bytes: usize,
    pub public_bytes: usize,
    pub proof_bytes_by_section: &'a [(&'a str, usize)],
    pub public_bytes_by_section: &'a [(&'a str, usize)],
    pub counters: &'a [(&'a str, usize)],
    pub verifier_timers: &'a [(&'a str, f64)],
    pub prover_timers: &'a [(&'a str, f64)],
}

#[doc(hidden)]
pub fn symbt3_instrumented_benchmark_json_value(
    row: &Symbt3InstrumentedBenchmarkJsonRow<'_>,
) -> Value {
    let mut object = Map::new();
    object.insert(
        "schema".to_owned(),
        Value::String(SYMBT3_INSTRUMENTED_BENCHMARK_JSON_SCHEMA.to_owned()),
    );
    object.insert("profile".to_owned(), Value::String(row.profile.to_owned()));
    object.insert(
        "route_kind".to_owned(),
        Value::String(row.route_kind.to_owned()),
    );
    object.insert("k_table".to_owned(), usize_value(row.k_table));
    object.insert("prove_ms".to_owned(), f64_value("prove_ms", row.prove_ms));
    object.insert(
        "verify_ms".to_owned(),
        f64_value("verify_ms", row.verify_ms),
    );
    object.insert("proof_bytes".to_owned(), usize_value(row.proof_bytes));
    object.insert("public_bytes".to_owned(), usize_value(row.public_bytes));
    object.insert(
        "proof_bytes_by_section".to_owned(),
        usize_object(row.proof_bytes_by_section),
    );
    object.insert(
        "public_bytes_by_section".to_owned(),
        usize_object(row.public_bytes_by_section),
    );
    object.insert("counters".to_owned(), usize_object(row.counters));
    object.insert(
        "verifier_timers".to_owned(),
        f64_object(row.verifier_timers),
    );
    object.insert("prover_timers".to_owned(), f64_object(row.prover_timers));
    Value::Object(object)
}

#[doc(hidden)]
pub fn symbt3_instrumented_benchmark_json_line(
    row: &Symbt3InstrumentedBenchmarkJsonRow<'_>,
) -> String {
    serde_json::to_string(&symbt3_instrumented_benchmark_json_value(row))
        .expect("SYMBT3 instrumented benchmark row must serialize")
}

fn usize_value(value: usize) -> Value {
    Value::Number(Number::from(value as u64))
}

fn usize_object(fields: &[(&str, usize)]) -> Value {
    let mut object = Map::new();
    for &(key, value) in fields {
        object.insert(key.to_owned(), usize_value(value));
    }
    Value::Object(object)
}

fn f64_value(key: &str, value: f64) -> Value {
    assert!(
        value.is_finite() && value >= 0.0,
        "SYMBT3 instrumented benchmark timer {key} must be finite and non-negative"
    );
    Value::Number(
        Number::from_f64(value)
            .expect("finite SYMBT3 instrumented benchmark timer must encode as JSON"),
    )
}

fn f64_object(fields: &[(&str, f64)]) -> Value {
    let mut object = Map::new();
    for &(key, value) in fields {
        object.insert(key.to_owned(), f64_value(key, value));
    }
    Value::Object(object)
}
