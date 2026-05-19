pub fn whir_pcs_compact_canonical_bytes(proof: &WhirPcsProof<F, EF, WhirMmcs>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(b"WHIR_PCS_COMPACT_JSON_CBOR_V1");
    let value = serde_json::to_value(proof).ok()?;
    ciborium::into_writer(&value, &mut out).ok()?;
    Some(out)
}

pub fn whir_pcs_from_compact_canonical_bytes(
    bytes: &[u8],
) -> Option<WhirPcsProof<F, EF, WhirMmcs>> {
    let magic = b"WHIR_PCS_COMPACT_JSON_CBOR_V1";
    let payload = bytes.strip_prefix(magic)?;
    let value: serde_json::Value = ciborium::from_reader(std::io::Cursor::new(payload)).ok()?;
    serde_json::from_value(value).ok()
}

#[must_use]
pub fn symbt3_tuple_leaf_multi_oracle_proof_canonical_bytes_compact(
    proof: &Symbt3TupleLeafMultiOracleProof,
) -> Option<Vec<u8>> {
    let mut out = proof.metadata_canonical_bytes();
    let pcs_bytes = whir_pcs_compact_canonical_bytes(&proof.whir_pcs_proof)?;
    push_bytes(&mut out, &pcs_bytes);
    Some(out)
}

fn encoded_len(encode: impl FnOnce(&mut Vec<u8>)) -> usize {
    let mut out = Vec::new();
    encode(&mut out);
    out.len()
}

fn json_value_len(value: &serde_json::Value) -> usize {
    serde_json::to_vec(value)
        .expect("JSON value must serialize for byte accounting")
        .len()
}

fn json_object_field_len(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> usize {
    object.get(key).map_or(0, json_value_len)
}

fn whir_pcs_query_opening_json_sections(query: &serde_json::Value) -> (usize, usize, usize) {
    let Some(object) = query.as_object() else {
        return (0, 0, json_value_len(query));
    };
    let merkle_root_path_payload_bytes = json_object_field_len(object, "proof");
    let query_value_payload_bytes = json_object_field_len(object, "values");
    let accounted = merkle_root_path_payload_bytes + query_value_payload_bytes;
    let transcript_payload_bytes = json_value_len(query).saturating_sub(accounted);
    (
        merkle_root_path_payload_bytes,
        query_value_payload_bytes,
        transcript_payload_bytes,
    )
}

fn whir_pcs_query_array_json_sections(queries: &serde_json::Value) -> (usize, usize, usize) {
    let Some(queries) = queries.as_array() else {
        return (0, 0, json_value_len(queries));
    };
    queries.iter().fold((0, 0, 0), |mut acc, query| {
        let sections = whir_pcs_query_opening_json_sections(query);
        acc.0 += sections.0;
        acc.1 += sections.1;
        acc.2 += sections.2;
        acc
    })
}

fn whir_pcs_json_payload_sections(pcs_json: &serde_json::Value) -> (usize, usize, usize) {
    let Some(object) = pcs_json.as_object() else {
        return (0, 0, json_value_len(pcs_json));
    };
    let mut merkle_root_path_payload_bytes = json_object_field_len(object, "initial_commitment");
    let mut query_value_payload_bytes = 0;
    let mut transcript_payload_bytes = json_object_field_len(object, "initial_ood_answers")
        + json_object_field_len(object, "initial_sumcheck")
        + json_object_field_len(object, "final_poly")
        + json_object_field_len(object, "final_pow_witness")
        + json_object_field_len(object, "final_sumcheck");

    if let Some(rounds) = object.get("rounds").and_then(serde_json::Value::as_array) {
        for round in rounds {
            let Some(round_object) = round.as_object() else {
                transcript_payload_bytes += json_value_len(round);
                continue;
            };
            merkle_root_path_payload_bytes += json_object_field_len(round_object, "commitment");
            transcript_payload_bytes += json_object_field_len(round_object, "ood_answers")
                + json_object_field_len(round_object, "pow_witness")
                + json_object_field_len(round_object, "sumcheck");
            if let Some(queries) = round_object.get("queries") {
                let query_sections = whir_pcs_query_array_json_sections(queries);
                merkle_root_path_payload_bytes += query_sections.0;
                query_value_payload_bytes += query_sections.1;
                transcript_payload_bytes += query_sections.2;
            }
        }
    }

    if let Some(final_queries) = object.get("final_queries") {
        let query_sections = whir_pcs_query_array_json_sections(final_queries);
        merkle_root_path_payload_bytes += query_sections.0;
        query_value_payload_bytes += query_sections.1;
        transcript_payload_bytes += query_sections.2;
    }

    (
        merkle_root_path_payload_bytes,
        query_value_payload_bytes,
        transcript_payload_bytes,
    )
}

