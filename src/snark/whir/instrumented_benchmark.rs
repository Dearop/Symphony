//! SYMBT3 instrumented benchmark JSONL contract helpers.
//!
//! This module is benchmark instrumentation only. It does not define or alter
//! WHIR proof payload bytes, public proof envelopes, product routing, or SYMBT3
//! verifier semantics.

use serde_json::{Map, Number, Value};

pub const SYMBT3_INSTRUMENTED_BENCHMARK_JSON_SCHEMA: &str =
    "symphony.symbt3.instrumented_benchmark.v1";
pub const SYMBT3_INSTRUMENTED_MULTI_ORACLE_JSON_SCHEMA: &str =
    "symphony.symbt3.instrumented_multi_oracle.v1";

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

pub const SYMBT3_INSTRUMENTED_MULTI_ORACLE_REQUIRED_TOP_LEVEL_FIELDS: &[&str] = &[
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
    "multi_oracle",
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
pub struct Symbt3InstrumentedMultiOracleShape<'a> {
    pub logical_oracle_count: usize,
    pub native_multi_oracle: bool,
    pub logical_envelope: bool,
    pub compat_internal_pcs_payloads: bool,
    pub whir_instance_count: usize,
    pub query_schedule_count: usize,
    pub transcript_count: usize,
    pub root_count: usize,
    pub same_domain: bool,
    pub same_field: bool,
    pub same_rate: bool,
    pub same_folding_parameter: bool,
    pub tuple_leaf_layout: &'a str,
    pub batched_constraint_count: usize,
    pub rlc_tuple_leaf: bool,
    pub rlc_batching_bits: usize,
    pub dev_only: bool,
    pub product_verify_public_allowed: bool,
}

#[doc(hidden)]
pub struct Symbt3InstrumentedMultiOracleJsonRow<'a> {
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
    pub query_position_count: usize,
    pub merkle_path_proxy: usize,
    pub hash_estimate: usize,
    pub field_op_estimate: usize,
    pub single_oracle_verify_ms: f64,
    pub naive_n_times_single_oracle_verify_ms: f64,
    pub tuple_leaf_verify_ms: f64,
    pub ratio_vs_single: f64,
    pub ratio_vs_naive_n_times_single: f64,
    pub shape_guard_passed: bool,
    pub multi_oracle: Symbt3InstrumentedMultiOracleShape<'a>,
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

#[doc(hidden)]
pub fn symbt3_instrumented_multi_oracle_json_value(
    row: &Symbt3InstrumentedMultiOracleJsonRow<'_>,
) -> Value {
    let mut object = Map::new();
    object.insert(
        "schema".to_owned(),
        Value::String(SYMBT3_INSTRUMENTED_MULTI_ORACLE_JSON_SCHEMA.to_owned()),
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
    object.insert(
        "query_position_count".to_owned(),
        usize_value(row.query_position_count),
    );
    object.insert(
        "merkle_path_proxy".to_owned(),
        usize_value(row.merkle_path_proxy),
    );
    object.insert("hash_estimate".to_owned(), usize_value(row.hash_estimate));
    object.insert(
        "field_op_estimate".to_owned(),
        usize_value(row.field_op_estimate),
    );
    object.insert(
        "single_oracle_verify_ms".to_owned(),
        f64_value("single_oracle_verify_ms", row.single_oracle_verify_ms),
    );
    object.insert(
        "naive_n_times_single_oracle_verify_ms".to_owned(),
        f64_value(
            "naive_n_times_single_oracle_verify_ms",
            row.naive_n_times_single_oracle_verify_ms,
        ),
    );
    object.insert(
        "tuple_leaf_verify_ms".to_owned(),
        f64_value("tuple_leaf_verify_ms", row.tuple_leaf_verify_ms),
    );
    object.insert(
        "ratio_vs_single".to_owned(),
        f64_value("ratio_vs_single", row.ratio_vs_single),
    );
    object.insert(
        "ratio_vs_naive_n_times_single".to_owned(),
        f64_value(
            "ratio_vs_naive_n_times_single",
            row.ratio_vs_naive_n_times_single,
        ),
    );
    object.insert(
        "shape_guard_passed".to_owned(),
        bool_value(row.shape_guard_passed),
    );
    object.insert(
        "multi_oracle".to_owned(),
        multi_oracle_shape_value(&row.multi_oracle),
    );
    Value::Object(object)
}

#[doc(hidden)]
pub fn symbt3_instrumented_multi_oracle_json_line(
    row: &Symbt3InstrumentedMultiOracleJsonRow<'_>,
) -> String {
    serde_json::to_string(&symbt3_instrumented_multi_oracle_json_value(row))
        .expect("SYMBT3 instrumented multi-oracle benchmark row must serialize")
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

fn bool_value(value: bool) -> Value {
    Value::Bool(value)
}

fn multi_oracle_shape_value(shape: &Symbt3InstrumentedMultiOracleShape<'_>) -> Value {
    let mut object = Map::new();
    object.insert(
        "logical_oracle_count".to_owned(),
        usize_value(shape.logical_oracle_count),
    );
    object.insert(
        "native_multi_oracle".to_owned(),
        bool_value(shape.native_multi_oracle),
    );
    object.insert(
        "logical_envelope".to_owned(),
        bool_value(shape.logical_envelope),
    );
    object.insert(
        "compat_internal_pcs_payloads".to_owned(),
        bool_value(shape.compat_internal_pcs_payloads),
    );
    object.insert(
        "whir_instance_count".to_owned(),
        usize_value(shape.whir_instance_count),
    );
    object.insert(
        "query_schedule_count".to_owned(),
        usize_value(shape.query_schedule_count),
    );
    object.insert(
        "transcript_count".to_owned(),
        usize_value(shape.transcript_count),
    );
    object.insert("root_count".to_owned(), usize_value(shape.root_count));
    object.insert("same_domain".to_owned(), bool_value(shape.same_domain));
    object.insert("same_field".to_owned(), bool_value(shape.same_field));
    object.insert("same_rate".to_owned(), bool_value(shape.same_rate));
    object.insert(
        "same_folding_parameter".to_owned(),
        bool_value(shape.same_folding_parameter),
    );
    object.insert(
        "tuple_leaf_layout".to_owned(),
        Value::String(shape.tuple_leaf_layout.to_owned()),
    );
    object.insert(
        "batched_constraint_count".to_owned(),
        usize_value(shape.batched_constraint_count),
    );
    object.insert(
        "rlc_tuple_leaf".to_owned(),
        bool_value(shape.rlc_tuple_leaf),
    );
    object.insert(
        "rlc_batching_bits".to_owned(),
        usize_value(shape.rlc_batching_bits),
    );
    object.insert("dev_only".to_owned(), bool_value(shape.dev_only));
    object.insert(
        "product_verify_public_allowed".to_owned(),
        bool_value(shape.product_verify_public_allowed),
    );
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
