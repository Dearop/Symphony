#[cfg(feature = "whir")]
use serde_json::Value;

#[cfg(feature = "whir")]
use symphony::snark::whir::instrumented_benchmark::{
    symbt3_instrumented_benchmark_json_line, Symbt3InstrumentedBenchmarkJsonRow,
    SYMBT3_INSTRUMENTED_BENCHMARK_COUNTER_NAMES, SYMBT3_INSTRUMENTED_BENCHMARK_JSON_SCHEMA,
    SYMBT3_INSTRUMENTED_BENCHMARK_PROOF_SECTION_NAMES,
    SYMBT3_INSTRUMENTED_BENCHMARK_PROVER_TIMER_NAMES,
    SYMBT3_INSTRUMENTED_BENCHMARK_PUBLIC_SECTION_NAMES,
    SYMBT3_INSTRUMENTED_BENCHMARK_REQUIRED_TOP_LEVEL_FIELDS,
    SYMBT3_INSTRUMENTED_BENCHMARK_VERIFIER_TIMER_NAMES,
};

#[cfg(feature = "whir")]
#[test]
fn symbt3_instrumented_benchmark_json_schema_contract_is_stable() {
    let proof_sections = SYMBT3_INSTRUMENTED_BENCHMARK_PROOF_SECTION_NAMES
        .iter()
        .enumerate()
        .map(|(index, &name)| (name, 100 + index))
        .collect::<Vec<_>>();
    let public_sections = SYMBT3_INSTRUMENTED_BENCHMARK_PUBLIC_SECTION_NAMES
        .iter()
        .enumerate()
        .map(|(index, &name)| (name, 10 + index))
        .collect::<Vec<_>>();
    let counters = SYMBT3_INSTRUMENTED_BENCHMARK_COUNTER_NAMES
        .iter()
        .map(|&name| {
            let value = match name {
                "num_oracles"
                | "num_roots"
                | "top_level_whir_proof_count"
                | "backend_table_count" => 1,
                "family_columnar_subproof_count" => 0,
                _ => 2,
            };
            (name, value)
        })
        .collect::<Vec<_>>();
    let verifier_timers = SYMBT3_INSTRUMENTED_BENCHMARK_VERIFIER_TIMER_NAMES
        .iter()
        .enumerate()
        .map(|(index, &name)| (name, index as f64 / 10.0))
        .collect::<Vec<_>>();
    let prover_timers = SYMBT3_INSTRUMENTED_BENCHMARK_PROVER_TIMER_NAMES
        .iter()
        .enumerate()
        .map(|(index, &name)| (name, index as f64 / 10.0))
        .collect::<Vec<_>>();

    let line = symbt3_instrumented_benchmark_json_line(&Symbt3InstrumentedBenchmarkJsonRow {
        profile: "symbt3_accumulator_authority",
        route_kind: "symbt3_non_zk_integrity_product",
        k_table: 4,
        prove_ms: 25.078,
        verify_ms: 24.348,
        proof_bytes: 329_707,
        public_bytes: 18_715,
        proof_bytes_by_section: &proof_sections,
        public_bytes_by_section: &public_sections,
        counters: &counters,
        verifier_timers: &verifier_timers,
        prover_timers: &prover_timers,
    });
    let row: Value = serde_json::from_str(&line).expect("instrumented benchmark row must be JSON");

    let object = row
        .as_object()
        .expect("instrumented benchmark row must be an object");
    for &field in SYMBT3_INSTRUMENTED_BENCHMARK_REQUIRED_TOP_LEVEL_FIELDS {
        assert!(
            object.contains_key(field),
            "instrumented benchmark JSON row must contain top-level field {field}"
        );
    }

    assert_eq!(row["schema"], SYMBT3_INSTRUMENTED_BENCHMARK_JSON_SCHEMA);
    assert_u64(&row, "k_table");
    assert_non_negative_f64(&row, "prove_ms");
    assert_non_negative_f64(&row, "verify_ms");
    assert_u64(&row, "proof_bytes");
    assert_u64(&row, "public_bytes");

    assert_usize_object_has_names(
        &row["proof_bytes_by_section"],
        SYMBT3_INSTRUMENTED_BENCHMARK_PROOF_SECTION_NAMES,
    );
    assert_usize_object_has_names(
        &row["public_bytes_by_section"],
        SYMBT3_INSTRUMENTED_BENCHMARK_PUBLIC_SECTION_NAMES,
    );
    assert_usize_object_has_names(
        &row["counters"],
        SYMBT3_INSTRUMENTED_BENCHMARK_COUNTER_NAMES,
    );
    assert_f64_object_has_names(
        &row["verifier_timers"],
        SYMBT3_INSTRUMENTED_BENCHMARK_VERIFIER_TIMER_NAMES,
    );
    assert_f64_object_has_names(
        &row["prover_timers"],
        SYMBT3_INSTRUMENTED_BENCHMARK_PROVER_TIMER_NAMES,
    );

    assert_eq!(row["counters"]["num_oracles"], 1);
    assert_eq!(row["counters"]["num_roots"], 1);
    assert_eq!(row["counters"]["top_level_whir_proof_count"], 1);
    assert_eq!(row["counters"]["family_columnar_subproof_count"], 0);
    assert_eq!(row["counters"]["backend_table_count"], 1);
}

#[cfg(feature = "whir")]
fn assert_u64(row: &Value, field: &str) {
    assert!(
        row[field].as_u64().is_some(),
        "{field} must be an unsigned integer"
    );
}

#[cfg(feature = "whir")]
fn assert_non_negative_f64(row: &Value, field: &str) {
    let value = row[field]
        .as_f64()
        .unwrap_or_else(|| panic!("{field} must be a number"));
    assert!(value >= 0.0, "{field} must be non-negative");
}

#[cfg(feature = "whir")]
fn assert_usize_object_has_names(value: &Value, names: &[&str]) {
    let object = value.as_object().expect("field must be an object");
    for &name in names {
        assert!(object.contains_key(name), "object must contain {name}");
        assert!(
            object[name].as_u64().is_some(),
            "object field {name} must be an unsigned integer"
        );
    }
}

#[cfg(feature = "whir")]
fn assert_f64_object_has_names(value: &Value, names: &[&str]) {
    let object = value.as_object().expect("field must be an object");
    for &name in names {
        assert!(object.contains_key(name), "object must contain {name}");
        let timer = object[name]
            .as_f64()
            .unwrap_or_else(|| panic!("timer {name} must be a number"));
        assert!(timer >= 0.0, "timer {name} must be non-negative");
    }
}
