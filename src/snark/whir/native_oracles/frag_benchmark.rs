pub fn build_native_oracle_benchmark_specs(
    oracle_count: usize,
    num_vars_per_oracle: usize,
) -> Option<Vec<WhirNativeOracleSpec>> {
    if oracle_count == 0 || num_vars_per_oracle == 0 {
        return None;
    }
    Some(
        (0..oracle_count)
            .map(|oracle_index| {
                let oracle_id = 10_000u32.checked_add(oracle_index as u32)?;
                let mut layout_bytes = Vec::new();
                push_bytes(&mut layout_bytes, b"SYMBT3_N1BENCH_NATIVE_ORACLE_LAYOUT_V1");
                push_u32(&mut layout_bytes, oracle_id);
                push_u64(&mut layout_bytes, num_vars_per_oracle as u64);
                Some(WhirNativeOracleSpec {
                    version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
                    oracle_id,
                    role: WhirNativeOracleRole::Auxiliary,
                    layout_digest: digest_bytes(&layout_bytes),
                    num_vars: num_vars_per_oracle,
                    opening_schedule: WhirNativeOpeningSchedule::TranscriptDerived {
                        domain_separator: "SYMBT3_N1BENCH_NATIVE_MULTI_ORACLE",
                    },
                })
            })
            .collect::<Option<Vec<_>>>()?,
    )
}

#[must_use]
pub fn build_native_oracle_batch_axis_benchmark_specs(
    round_count: usize,
    batch_log_size: usize,
    message_axis_log_size: usize,
) -> Option<Vec<WhirNativeOracleSpec>> {
    if round_count == 0 || message_axis_log_size == 0 {
        return None;
    }
    let total_num_vars = batch_log_size.checked_add(message_axis_log_size)?;
    if total_num_vars == 0 {
        return None;
    }
    Some(
        (0..round_count)
            .map(|round| {
                let round_u32 = u32::try_from(round).ok()?;
                let oracle_id = SYMBT3_N4_MESSAGE_ORACLE_ID_BASE.checked_add(round_u32)?;
                let mut layout_bytes = Vec::new();
                push_bytes(
                    &mut layout_bytes,
                    b"SYMBT3_N1BENCH_BATCH_AXIS_ORACLE_LAYOUT_V1",
                );
                push_u32(&mut layout_bytes, round_u32);
                push_u32(&mut layout_bytes, oracle_id);
                push_u64(&mut layout_bytes, batch_log_size as u64);
                push_u64(&mut layout_bytes, message_axis_log_size as u64);
                Some(WhirNativeOracleSpec {
                    version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
                    oracle_id,
                    role: WhirNativeOracleRole::MessageRound { round: round_u32 },
                    layout_digest: digest_bytes(&layout_bytes),
                    num_vars: total_num_vars,
                    opening_schedule: WhirNativeOpeningSchedule::TranscriptDerived {
                        domain_separator: "SYMBT3_N1BENCH_BATCH_AXIS_MESSAGE_VIEW",
                    },
                })
            })
            .collect::<Option<Vec<_>>>()?,
    )
}

#[must_use]
pub fn build_native_oracle_benchmark_eval_requests(
    specs: &[WhirNativeOracleSpec],
    claim_kind: WhirNativeEvalClaimKind,
) -> Vec<WhirNativeEvalRequest> {
    specs
        .iter()
        .map(|spec| WhirNativeEvalRequest {
            oracle_id: spec.oracle_id,
            claim_kind,
        })
        .collect()
}

#[must_use]
pub fn build_native_oracle_benchmark_evals(
    specs: &[WhirNativeOracleSpec],
    seed: u64,
) -> Option<Vec<Vec<BabyBear>>> {
    specs
        .iter()
        .enumerate()
        .map(|(oracle_index, spec)| {
            let shift = u32::try_from(spec.num_vars).ok()?;
            let len = 1usize.checked_shl(shift)?;
            Some(
                (0..len)
                    .map(|eval_index| {
                        BabyBear::from_u32(
                            ((seed + oracle_index as u64 * 1_000_003 + eval_index as u64 * 65_537)
                                % 2_000_000_000) as u32,
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

