#[cfg(feature = "whir")]
use std::fs;
#[cfg(feature = "whir")]
use std::path::Path;

#[cfg(feature = "whir")]
use serde_json::Value;

#[cfg(feature = "whir")]
use symphony::snark::whir::instrumented_benchmark::{
    symbt3_instrumented_multi_oracle_json_line, Symbt3InstrumentedMultiOracleJsonRow,
    Symbt3InstrumentedMultiOracleShape, SYMBT3_INSTRUMENTED_MULTI_ORACLE_JSON_SCHEMA,
    SYMBT3_INSTRUMENTED_MULTI_ORACLE_REQUIRED_TOP_LEVEL_FIELDS,
};

#[cfg(feature = "whir")]
const JSONL_PATH: &str = "benchmarks/symbt3_instrumented_multi_oracle.jsonl";

#[cfg(feature = "whir")]
#[test]
fn symbt3_instrumented_multi_oracle_json_schema_contract_is_stable() {
    let proof_sections = [
        ("native_metadata", 128usize),
        ("native_pcs_payloads", 512),
        ("native_oracle_descriptors", 256),
    ];
    let public_sections = [
        ("native_oracle_descriptors", 256usize),
        ("native_oracle_roots", 64),
        ("native_transcript_context", 96),
    ];
    let counters = [
        ("num_oracles", 2usize),
        ("num_roots", 2),
        ("num_query_positions", 2),
        ("num_merkle_paths", 8),
        ("num_hashes_estimate", 18),
        ("num_field_ops_estimate", 32),
        ("num_extension_field_ops_estimate", 0),
        ("peak_alloc_bytes", 2048),
        ("top_level_whir_proof_count", 1),
        ("family_columnar_subproof_count", 0),
        ("backend_table_count", 0),
        ("source_r1cs_residual_verifier_evaluations", 0),
        ("native_oracle_count", 2),
        ("native_oracle_pcs_opening_count", 2),
        ("native_oracle_descriptor_bytes", 256),
        ("native_oracle_eval_claim_count", 2),
        ("native_oracle_opening_count", 2),
    ];
    let verifier_timers = [
        ("native_oracle_verify_ms", 0.12),
        ("merkle_root_path_verification", 0.12),
    ];
    let prover_timers = [
        ("native_oracle_prove_ms", 0.95),
        ("whir_folding_layers", 0.95),
    ];
    let line = symbt3_instrumented_multi_oracle_json_line(&Symbt3InstrumentedMultiOracleJsonRow {
        profile: "symbt3_m1a_instrumented_multi_oracle",
        route_kind: "logical_multi_oracle_compat_envelope",
        k_table: 4,
        prove_ms: 0.95,
        verify_ms: 0.12,
        proof_bytes: 896,
        public_bytes: 416,
        proof_bytes_by_section: &proof_sections,
        public_bytes_by_section: &public_sections,
        counters: &counters,
        verifier_timers: &verifier_timers,
        prover_timers: &prover_timers,
        query_position_count: 2,
        merkle_path_proxy: 8,
        hash_estimate: 18,
        field_op_estimate: 32,
        single_oracle_verify_ms: 0.12,
        naive_n_times_single_oracle_verify_ms: 0.24,
        tuple_leaf_verify_ms: 0.0,
        ratio_vs_single: 1.0,
        ratio_vs_naive_n_times_single: 0.5,
        shape_guard_passed: true,
        multi_oracle: Symbt3InstrumentedMultiOracleShape {
            logical_oracle_count: 2,
            native_multi_oracle: false,
            logical_envelope: true,
            compat_internal_pcs_payloads: true,
            whir_instance_count: 2,
            query_schedule_count: 2,
            transcript_count: 2,
            root_count: 2,
            same_domain: true,
            same_field: true,
            same_rate: true,
            same_folding_parameter: true,
            tuple_leaf_layout: "none",
            batched_constraint_count: 0,
            rlc_tuple_leaf: false,
            rlc_batching_bits: 0,
            dev_only: true,
            product_verify_public_allowed: false,
        },
    });
    let row: Value =
        serde_json::from_str(&line).expect("instrumented multi-oracle row must be JSON");
    assert_valid_multi_oracle_row(&row);

    let tuple_line =
        symbt3_instrumented_multi_oracle_json_line(&Symbt3InstrumentedMultiOracleJsonRow {
            profile: "symbt3_m1b_same_domain_rlc_tuple_leaf",
            route_kind: "same_domain_rlc_tuple_leaf_native",
            k_table: 4,
            prove_ms: 1.10,
            verify_ms: 0.14,
            proof_bytes: 640,
            public_bytes: 320,
            proof_bytes_by_section: &proof_sections,
            public_bytes_by_section: &public_sections,
            counters: &counters,
            verifier_timers: &verifier_timers,
            prover_timers: &prover_timers,
            query_position_count: 1,
            merkle_path_proxy: 4,
            hash_estimate: 9,
            field_op_estimate: 64,
            single_oracle_verify_ms: 0.12,
            naive_n_times_single_oracle_verify_ms: 0.24,
            tuple_leaf_verify_ms: 0.14,
            ratio_vs_single: 1.166,
            ratio_vs_naive_n_times_single: 0.583,
            shape_guard_passed: true,
            multi_oracle: Symbt3InstrumentedMultiOracleShape {
                logical_oracle_count: 2,
                native_multi_oracle: true,
                logical_envelope: false,
                compat_internal_pcs_payloads: false,
                whir_instance_count: 1,
                query_schedule_count: 1,
                transcript_count: 1,
                root_count: 1,
                same_domain: true,
                same_field: true,
                same_rate: true,
                same_folding_parameter: true,
                tuple_leaf_layout: "same_domain_rlc_tuple_leaf_v1",
                batched_constraint_count: 2,
                rlc_tuple_leaf: true,
                rlc_batching_bits: 31,
                dev_only: true,
                product_verify_public_allowed: false,
            },
        });
    let tuple_row: Value =
        serde_json::from_str(&tuple_line).expect("tuple-leaf multi-oracle row must be JSON");
    assert_valid_multi_oracle_row(&tuple_row);
}

#[cfg(feature = "whir")]
#[test]
fn symbt3_instrumented_multi_oracle_jsonl_rows_parse_when_present() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(JSONL_PATH);
    if !path.exists() {
        return;
    }

    let contents = fs::read_to_string(&path).expect("read instrumented multi-oracle JSONL");
    let mut parsed = 0usize;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let json = line
            .strip_prefix("SYMBT3_INSTRUMENTED_MULTI_ORACLE_JSON,")
            .unwrap_or(line);
        let row: Value =
            serde_json::from_str(json).expect("instrumented multi-oracle JSONL row parses");
        assert_valid_multi_oracle_row(&row);
        parsed += 1;
    }
    assert!(parsed > 0, "JSONL file exists but contained no rows");
}

#[cfg(feature = "whir")]
fn assert_valid_multi_oracle_row(row: &Value) {
    let object = row
        .as_object()
        .expect("instrumented multi-oracle row must be an object");
    for &field in SYMBT3_INSTRUMENTED_MULTI_ORACLE_REQUIRED_TOP_LEVEL_FIELDS {
        assert!(
            object.contains_key(field),
            "instrumented multi-oracle row must contain {field}"
        );
    }

    assert_eq!(row["schema"], SYMBT3_INSTRUMENTED_MULTI_ORACLE_JSON_SCHEMA);
    assert!(row["k_table"].as_u64().is_some());
    assert!(row["prove_ms"].as_f64().is_some_and(|value| value >= 0.0));
    assert!(row["verify_ms"].as_f64().is_some_and(|value| value >= 0.0));
    assert!(row["proof_bytes"].as_u64().is_some());
    assert!(row["public_bytes"].as_u64().is_some());
    assert!(row["query_position_count"].as_u64().is_some());
    assert!(row["merkle_path_proxy"].as_u64().is_some());
    assert!(row["hash_estimate"].as_u64().is_some());
    assert!(row["field_op_estimate"].as_u64().is_some());

    let multi = row["multi_oracle"]
        .as_object()
        .expect("multi_oracle must be an object");
    let logical_count = multi["logical_oracle_count"]
        .as_u64()
        .expect("logical_oracle_count must be integer");
    assert!(row["single_oracle_verify_ms"]
        .as_f64()
        .is_some_and(|value| value >= 0.0));
    assert!(row["naive_n_times_single_oracle_verify_ms"]
        .as_f64()
        .is_some_and(|value| value >= 0.0));
    assert!(row["tuple_leaf_verify_ms"]
        .as_f64()
        .is_some_and(|value| value >= 0.0));
    assert!(row["ratio_vs_single"]
        .as_f64()
        .is_some_and(|value| value >= 0.0));
    assert!(row["ratio_vs_naive_n_times_single"]
        .as_f64()
        .is_some_and(|value| value >= 0.0));
    assert!(row["shape_guard_passed"].as_bool().unwrap());

    let native_multi_oracle = multi["native_multi_oracle"].as_bool().unwrap();
    let tuple_leaf_layout = multi["tuple_leaf_layout"]
        .as_str()
        .expect("tuple_leaf_layout must be string");
    if native_multi_oracle {
        assert!(!multi["logical_envelope"].as_bool().unwrap());
        assert!(!multi["compat_internal_pcs_payloads"].as_bool().unwrap());
        assert_eq!(multi["whir_instance_count"].as_u64().unwrap(), 1);
        assert_eq!(multi["query_schedule_count"].as_u64().unwrap(), 1);
        assert_eq!(multi["transcript_count"].as_u64().unwrap(), 1);
        assert_eq!(multi["root_count"].as_u64().unwrap(), 1);
        assert!(matches!(
            tuple_leaf_layout,
            "same_domain_rlc_tuple_leaf_v1" | "same_domain_tuple_leaf_v1"
        ));
        assert!(multi["rlc_tuple_leaf"].as_bool().is_some());
    } else if tuple_leaf_layout == "none" {
        assert!(multi["logical_envelope"].as_bool().unwrap());
        assert!(multi["compat_internal_pcs_payloads"].as_bool().unwrap());
        assert_eq!(
            multi["whir_instance_count"].as_u64().unwrap(),
            logical_count
        );
        assert_eq!(
            multi["query_schedule_count"].as_u64().unwrap(),
            logical_count
        );
        assert_eq!(multi["transcript_count"].as_u64().unwrap(), logical_count);
        assert_eq!(multi["root_count"].as_u64().unwrap(), logical_count);
        assert!(!multi["rlc_tuple_leaf"].as_bool().unwrap());
    } else {
        assert_eq!(logical_count, 1);
        assert_eq!(multi["whir_instance_count"].as_u64().unwrap(), 1);
        assert_eq!(multi["root_count"].as_u64().unwrap(), 1);
    }
    assert!(!multi["product_verify_public_allowed"].as_bool().unwrap());
}
