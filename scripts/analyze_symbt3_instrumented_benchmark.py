#!/usr/bin/env python3
"""Print a compact summary of SYMBT3 instrumented benchmark JSONL rows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PATH = Path("benchmarks/symbt3_instrumented_benchmark.jsonl")
PREFIX = "SYMBT3_INSTRUMENTED_BENCHMARK_JSON,"
SCHEMA = "symphony.symbt3.instrumented_benchmark.v1"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize the single-oracle K6a SYMBT3 instrumented benchmark JSONL baseline."
        )
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

    table = [
        [
            str(as_int(row.get("k_table"), "n/a")),
            format_ms(row.get("prove_ms")),
            format_ms(row.get("verify_ms")),
            format_bytes(first_present(row, "proof_bytes", "proof_bytes_total")),
            format_bytes(first_present(row, "public_bytes", "public_bytes_total")),
            counter_summary(as_dict(row.get("counters"))),
            section_summary(
                as_dict(row.get("proof_bytes_by_section")),
                ["whir_pcs_json", "sumcheck_rounds_4", "private_opening_evals"],
            ),
            section_summary(
                as_dict(row.get("public_bytes_by_section")),
                ["folded_values", "accumulator_boundary", "relation_and_output_digests"],
            ),
        ]
        for row in rows
    ]
    print_table(
        [
            "k_table",
            "prove_ms",
            "verify_ms",
            "proof_bytes",
            "public_bytes",
            "counters",
            "proof_sections",
            "public_sections",
        ],
        table,
    )
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


def warn(path: Path, line_number: int, message: str) -> None:
    print(f"{path}:{line_number}: skipped row: {message}", file=sys.stderr)


def first_present(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row:
            return row[key]
    return None


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


def format_ms(value: Any) -> str:
    number = as_float(value)
    if number is None or number < 0:
        return "n/a"
    return f"{number:.3f}"


def format_bytes(value: Any) -> str:
    number = as_int(value, None)
    if number is None or number < 0:
        return "n/a"
    return f"{number:,}"


def counter_summary(counters: dict[str, Any]) -> str:
    keys = [
        ("oracles", "num_oracles"),
        ("roots", "num_roots"),
        ("queries", "num_query_positions"),
        ("paths", "num_merkle_paths"),
        ("top", "top_level_whir_proof_count"),
        ("family", "family_columnar_subproof_count"),
        ("tables", "backend_table_count"),
        ("src_eval", "source_r1cs_residual_verifier_evaluations"),
    ]
    return " ".join(f"{label}={format_counter(counters.get(key))}" for label, key in keys)


def format_counter(value: Any) -> str:
    number = as_int(value, None)
    return "n/a" if number is None or number < 0 else str(number)


def section_summary(sections: dict[str, Any], names: list[str]) -> str:
    parts = []
    for name in names:
        value = as_int(sections.get(name), None)
        if value is not None and value >= 0:
            parts.append(f"{name}={value:,}")
    return " ".join(parts) if parts else "n/a"


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
