#!/usr/bin/env python3
"""Analyze SYMBT3 instrumented multi-oracle benchmark JSONL rows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PATH = Path("benchmarks/symbt3_instrumented_multi_oracle.jsonl")
PREFIX = "SYMBT3_INSTRUMENTED_MULTI_ORACLE_JSON,"
SCHEMA = "symphony.symbt3.instrumented_multi_oracle.v1"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize SYMBT3 M1a/M1b instrumented multi-oracle benchmark rows."
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=DEFAULT_PATH,
        help=f"JSONL input path, default: {DEFAULT_PATH}",
    )
    args = parser.parse_args()

    rows = read_rows(args.path)
    if not rows:
        print(f"No valid {SCHEMA} rows found in {args.path}", file=sys.stderr)
        return 0

    baselines: dict[tuple[int, str], float] = {}
    for row in rows:
        k_table = as_int(row.get("k_table"), None)
        multi = as_dict(row.get("multi_oracle"))
        logical_count = as_int(multi.get("logical_oracle_count"), None)
        verify_ms = as_float(row.get("verify_ms"))
        if k_table is not None and logical_count == 1 and verify_ms is not None:
            baselines[(k_table, shape_family(multi))] = verify_ms

    table: list[list[str]] = []
    warnings: list[str] = []
    for row in rows:
        k_table = as_int(row.get("k_table"), 0)
        multi = as_dict(row.get("multi_oracle"))
        logical_count = as_int(multi.get("logical_oracle_count"), 0)
        verify_ms = as_float(row.get("verify_ms")) or 0.0
        family = shape_family(multi)
        single_ms = baselines.get((k_table, family), verify_ms if logical_count == 1 else 0.0)
        naive_ms = single_ms * logical_count
        true_native_shape = is_true_native_shape(multi)
        shape_guard_passed = honest_shape_guard(multi)
        warning = native_shape_warning(multi)
        if warning:
            warnings.append(f"k={k_table} n={logical_count}: {warning}")
        table.append(
            [
                str(k_table),
                family,
                str(logical_count),
                format_ms(verify_ms),
                format_ms(single_ms),
                format_ms(naive_ms),
                format_ratio(verify_ms, single_ms),
                format_ratio(verify_ms, naive_ms),
                str(shape_guard_passed).lower(),
                str(true_native_shape).lower(),
                str(bool(multi.get("native_multi_oracle"))).lower(),
                str(as_int(multi.get("whir_instance_count"), "n/a")),
                str(as_int(multi.get("root_count"), "n/a")),
                str(multi.get("tuple_leaf_layout", "n/a")),
            ]
        )

    print_table(
        [
            "k_table",
            "mode",
            "logical_oracles",
            "native_multi_oracle_verify_ms",
            "single_oracle_verify_ms",
            "n_times_single_oracle_verify_ms",
            "ratio_vs_single",
            "ratio_vs_naive_n_times_single",
            "shape_guard_passed",
            "true_native_shape",
            "native_multi_oracle",
            "whir_instance_count",
            "root_count",
            "tuple_leaf_layout",
        ],
        table,
    )
    if warnings:
        print("\nWarnings:", file=sys.stderr)
        for warning in warnings:
            print(f"  {warning}", file=sys.stderr)
    return 0


def read_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        print(f"Missing benchmark file: {path}", file=sys.stderr)
        return []

    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith(PREFIX):
                line = line[len(PREFIX) :]
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                warn(path, line_number, f"malformed JSON: {error.msg}")
                continue
            if not isinstance(value, dict):
                warn(path, line_number, "row is not a JSON object")
                continue
            if value.get("schema") != SCHEMA:
                warn(path, line_number, f"unexpected schema {value.get('schema')!r}")
                continue
            rows.append(value)
    return rows


def is_true_native_shape(multi: dict[str, Any]) -> bool:
    return (
        multi.get("native_multi_oracle") is True
        and as_int(multi.get("logical_oracle_count"), 0) > 1
        and multi.get("logical_envelope") is False
        and multi.get("compat_internal_pcs_payloads") is False
        and as_int(multi.get("whir_instance_count"), 0) == 1
        and as_int(multi.get("query_schedule_count"), 0) == 1
        and as_int(multi.get("transcript_count"), 0) == 1
        and as_int(multi.get("root_count"), 0) == 1
        and (
            multi.get("tuple_leaf_layout")
            in ("same_domain_tuple_leaf_v1", "same_domain_rlc_tuple_leaf_v1")
        )
    )


def honest_shape_guard(multi: dict[str, Any]) -> bool:
    native_claimed = bool(multi.get("native_multi_oracle"))
    return native_claimed == is_true_native_shape(multi)


def shape_family(multi: dict[str, Any]) -> str:
    layout = multi.get("tuple_leaf_layout")
    if layout in ("same_domain_tuple_leaf_v1", "same_domain_rlc_tuple_leaf_v1"):
        return "tuple_leaf"
    return "compat"


def native_shape_warning(multi: dict[str, Any]) -> str | None:
    if not bool(multi.get("native_multi_oracle")):
        return None
    bad_fields = []
    for field in (
        "whir_instance_count",
        "root_count",
        "query_schedule_count",
        "transcript_count",
    ):
        if as_int(multi.get(field), 0) != 1:
            bad_fields.append(field)
    if bad_fields:
        return "native_multi_oracle=true but " + ", ".join(bad_fields) + " != 1"
    return None


def warn(path: Path, line_number: int, message: str) -> None:
    print(f"{path}:{line_number}: skipped row: {message}", file=sys.stderr)


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_int(value: Any, fallback: Any = 0) -> Any:
    if isinstance(value, bool):
        return fallback
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return fallback


def as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def format_ms(value: float) -> str:
    return f"{value:.3f}" if value >= 0.0 else "n/a"


def format_ratio(numerator: float, denominator: float) -> str:
    if denominator <= 0.0:
        return "n/a"
    return f"{numerator / denominator:.3f}"


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)))


if __name__ == "__main__":
    raise SystemExit(main())
