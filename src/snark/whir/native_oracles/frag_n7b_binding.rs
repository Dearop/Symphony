pub fn build_symbt3_n7b_full_authority_binding_digest(
    inputs: &Symbt3N7bFullAuthorityBindingInputs,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_N7B_FULL_NATIVE_ACCUMULATOR_AUTHORITY_BINDING_V1",
    );
    push_bytes(&mut bytes, &inputs.workload_kind.canonical_bytes());
    push_digest(&mut bytes, &inputs.profile_digest);
    push_digest(&mut bytes, &inputs.accumulator_instance_digest);
    push_digest(&mut bytes, &inputs.public_statement_digest);
    push_digest(&mut bytes, &inputs.whir_param_digest);
    push_digest(&mut bytes, &inputs.main_symbt3_relation_id);
    push_digest(&mut bytes, &inputs.main_symbt3_proof_digest);
    push_digest(&mut bytes, &inputs.tuple_leaf_root);
    push_digest(&mut bytes, &inputs.tuple_leaf_layout_digest);
    push_digest(&mut bytes, &inputs.native_oracle_descriptor_digest);
    push_digest(&mut bytes, &inputs.native_message_roots_digest);
    push_digest(&mut bytes, &inputs.manifest_oracle_root);
    push_digest(&mut bytes, &inputs.source_oracle_root);
    push_digest(&mut bytes, &inputs.batch_manifest_root);
    push_digest(&mut bytes, &inputs.old_accumulator_digest);
    push_digest(&mut bytes, &inputs.new_accumulator_digest);
    push_u64(&mut bytes, inputs.batch_size);
    push_u64(&mut bytes, inputs.active_count);
    digest_bytes(&bytes)
}
