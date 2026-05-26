#!/usr/bin/env python3
"""Plot SYMBT3 asymptotic-scaling benchmark output."""

import math
import sys
import csv
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import pandas as pd

    HAVE_PLOT_LIBS = True
except ModuleNotFoundError:
    plt = None
    pd = None
    HAVE_PLOT_LIBS = False


def _to_number(value):
    try:
        if value == "":
            return float("nan")
        as_float = float(value)
        if as_float.is_integer():
            return int(as_float)
        return as_float
    except (TypeError, ValueError):
        return value


def load_rows(csv_path):
    with csv_path.open(newline="", encoding="utf-8") as handle:
        return [
            {key: _to_number(value) for key, value in row.items()}
            for row in csv.DictReader(handle)
        ]


def fit_loglog_slope_rows(rows, metric):
    points = [
        (float(row["k"]), float(row[metric]))
        for row in rows
        if metric in row and row["k"] and row[metric] and row[metric] > 0
    ]
    if len(points) < 2:
        return float("nan")
    xs = [math.log2(x) for x, _ in points]
    ys = [math.log2(y) for _, y in points]
    xbar = sum(xs) / len(xs)
    ybar = sum(ys) / len(ys)
    num = sum((x - xbar) * (y - ybar) for x, y in zip(xs, ys))
    den = sum((x - xbar) ** 2 for x in xs)
    return num / den if den else float("nan")


def write_svg_line(rows, outdir, metric, logy=False):
    if not rows or metric not in rows[0]:
        return
    points = [
        (float(row["k"]), float(row[metric]))
        for row in rows
        if row.get("k", 0) > 0 and row.get(metric, 0) == row.get(metric, 0)
    ]
    points = [(x, y) for x, y in points if y > 0 or not logy]
    if not points:
        return

    width, height = 900, 520
    left, right, top, bottom = 80, 30, 60, 70
    xs = [math.log2(x) for x, _ in points]
    ys = [math.log2(y) if logy and y > 0 else y for _, y in points]
    xmin, xmax = min(xs), max(xs)
    ymin, ymax = min(ys), max(ys)
    if xmin == xmax:
        xmax += 1.0
    if ymin == ymax:
        ymax += 1.0

    def sx(x):
        return left + (math.log2(x) - xmin) / (xmax - xmin) * (width - left - right)

    def sy(y):
        vy = math.log2(y) if logy and y > 0 else y
        return height - bottom - (vy - ymin) / (ymax - ymin) * (height - top - bottom)

    slope = fit_loglog_slope_rows(rows, metric)
    title = f"{metric} vs k"
    if not math.isnan(slope):
        title += f" | log-log slope ~= {slope:.3f}"
    if logy:
        title += " | log-log"

    polyline = " ".join(f"{sx(x):.2f},{sy(y):.2f}" for x, y in points)
    circles = "\n".join(
        f'<circle cx="{sx(x):.2f}" cy="{sy(y):.2f}" r="4" fill="#1f77b4" />'
        for x, y in points
    )
    xticks = "\n".join(
        f'<text x="{sx(x):.2f}" y="{height - 35}" font-size="12" text-anchor="middle">{int(x)}</text>'
        for x, _ in points
    )
    filename = f"{metric}{'_loglog' if logy else ''}.svg"
    (outdir / filename).write_text(
        f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<rect width="100%" height="100%" fill="white"/>
<text x="{width/2}" y="30" font-size="18" text-anchor="middle">{title}</text>
<line x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}" stroke="black"/>
<line x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}" stroke="black"/>
<text x="{width/2}" y="{height-10}" font-size="14" text-anchor="middle">k</text>
<text x="18" y="{height/2}" font-size="14" text-anchor="middle" transform="rotate(-90 18 {height/2})">{metric}</text>
{xticks}
<polyline points="{polyline}" fill="none" stroke="#1f77b4" stroke-width="2"/>
{circles}
</svg>
""",
        encoding="utf-8",
    )


def write_svg_ratios(rows, outdir, metrics):
    rows = sorted(rows, key=lambda row: row["k"])
    ratio_rows = []
    for prev, cur in zip(rows, rows[1:]):
        if cur["k"] != 2 * prev["k"]:
            continue
        row = {"k": cur["k"]}
        for metric in metrics:
            if metric in cur and prev.get(metric, 0) > 0:
                row[f"{metric}_ratio"] = cur[metric] / prev[metric]
        ratio_rows.append(row)
    if not ratio_rows:
        return
    with (outdir / "doubling_ratios.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(ratio_rows[0].keys()))
        writer.writeheader()
        writer.writerows(ratio_rows)

    # A compact SVG ratio plot.
    width, height = 900, 520
    left, right, top, bottom = 80, 180, 60, 70
    xs = [math.log2(row["k"]) for row in ratio_rows]
    vals = [
        (metric, [row.get(f"{metric}_ratio", float("nan")) for row in ratio_rows])
        for metric in metrics
    ]
    ys = [value for _, series in vals for value in series if value == value]
    ymin, ymax = min([1.0, *ys]), max([2.0, *ys])
    xmin, xmax = min(xs), max(xs)
    if xmin == xmax:
        xmax += 1.0

    def sx(k):
        return left + (math.log2(k) - xmin) / (xmax - xmin) * (width - left - right)

    def sy(value):
        return height - bottom - (value - ymin) / (ymax - ymin) * (height - top - bottom)

    colors = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e"]
    parts = [
        f'<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{width/2}" y="30" font-size="18" text-anchor="middle">Doubling ratios: metric(k) / metric(k/2)</text>',
        f'<line x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}" stroke="black"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}" stroke="black"/>',
        f'<line x1="{left}" y1="{sy(1.0):.2f}" x2="{width-right}" y2="{sy(1.0):.2f}" stroke="#999" stroke-dasharray="5,5"/>',
        f'<line x1="{left}" y1="{sy(2.0):.2f}" x2="{width-right}" y2="{sy(2.0):.2f}" stroke="#999" stroke-dasharray="5,5"/>',
    ]
    for idx, (metric, series) in enumerate(vals):
        color = colors[idx % len(colors)]
        clean = [(ratio_rows[i]["k"], value) for i, value in enumerate(series) if value == value]
        if not clean:
            continue
        polyline = " ".join(f"{sx(k):.2f},{sy(value):.2f}" for k, value in clean)
        parts.append(f'<polyline points="{polyline}" fill="none" stroke="{color}" stroke-width="2"/>')
        parts.append(
            f'<text x="{width-right+10}" y="{top + 20 * idx}" font-size="12" fill="{color}">{metric}</text>'
        )
    (outdir / "doubling_ratios.svg").write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">\n'
        + "\n".join(parts)
        + "\n</svg>\n",
        encoding="utf-8",
    )


def write_svg_guardrails(rows, outdir):
    guard_cols = [
        "top_level_whir_proof_count",
        "family_columnar_subproof_count",
        "backend_table_count",
        "message_to_trace_binding_count",
    ]
    for metric in guard_cols:
        write_svg_line(rows, outdir, metric)
    width, height = 900, 520
    left, right, top, bottom = 80, 180, 60, 70
    xs = [math.log2(row["k"]) for row in rows]
    values = [row.get(col, 0) for row in rows for col in guard_cols]
    ymin, ymax = min(values + [0]), max(values + [1])
    xmin, xmax = min(xs), max(xs)
    if xmin == xmax:
        xmax += 1.0

    def sx(k):
        return left + (math.log2(k) - xmin) / (xmax - xmin) * (width - left - right)

    def sy(value):
        return height - bottom - (value - ymin) / (ymax - ymin) * (height - top - bottom)

    colors = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd"]
    parts = [
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{width/2}" y="30" font-size="18" text-anchor="middle">Architecture guardrails</text>',
        f'<line x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}" stroke="black"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}" stroke="black"/>',
    ]
    for idx, col in enumerate(guard_cols):
        color = colors[idx % len(colors)]
        polyline = " ".join(f"{sx(row['k']):.2f},{sy(row.get(col, 0)):.2f}" for row in rows)
        parts.append(f'<polyline points="{polyline}" fill="none" stroke="{color}" stroke-width="2"/>')
        parts.append(
            f'<text x="{width-right+10}" y="{top + 20 * idx}" font-size="12" fill="{color}">{col}</text>'
        )
    (outdir / "architecture_guardrails.svg").write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">\n'
        + "\n".join(parts)
        + "\n</svg>\n",
        encoding="utf-8",
    )


def write_svg_verifier_breakdown(rows, outdir):
    cols = [
        "verify_whir_pcs_ms",
        "verify_transcript_ms",
        "verify_sumcheck_rounds_ms",
        "verify_final_constraint_eval_ms",
        "verify_final_eval_manifest_ms",
        "verify_final_eval_source_r1cs_ms",
        "verify_final_eval_folded_boundary_ms",
        "verify_final_eval_product_residual_ms",
        "verify_final_eval_ajtai_ms",
        "verify_final_eval_range_ms",
        "verify_final_eval_message_view_ms",
    ]
    cols = [col for col in cols if rows and col in rows[0]]
    if not cols:
        return
    width, height = 1000, 560
    left, right, top, bottom = 80, 260, 60, 70
    totals = [sum(float(row.get(col, 0.0)) for col in cols) for row in rows]
    ymax = max(totals + [1.0])
    bar_w = max(24, (width - left - right) / max(len(rows), 1) * 0.55)
    colors = [
        "#1f77b4",
        "#ff7f0e",
        "#2ca02c",
        "#d62728",
        "#9467bd",
        "#8c564b",
        "#e377c2",
        "#7f7f7f",
        "#bcbd22",
        "#17becf",
        "#393b79",
    ]

    def x_at(idx):
        span = width - left - right
        return left + (idx + 0.5) * span / max(len(rows), 1)

    def y_at(value):
        return height - bottom - value / ymax * (height - top - bottom)

    parts = [
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{width/2}" y="30" font-size="18" text-anchor="middle">Verifier time breakdown</text>',
        f'<line x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}" stroke="black"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}" stroke="black"/>',
    ]
    for idx, row in enumerate(rows):
        bottom_value = 0.0
        x = x_at(idx) - bar_w / 2
        for col_idx, col in enumerate(cols):
            value = float(row.get(col, 0.0))
            if value <= 0:
                continue
            y_top = y_at(bottom_value + value)
            y_bottom = y_at(bottom_value)
            parts.append(
                f'<rect x="{x:.2f}" y="{y_top:.2f}" width="{bar_w:.2f}" height="{y_bottom-y_top:.2f}" fill="{colors[col_idx % len(colors)]}"/>'
            )
            bottom_value += value
        parts.append(
            f'<text x="{x_at(idx):.2f}" y="{height-35}" font-size="12" text-anchor="middle">{int(row["k"])}</text>'
        )
    for idx, col in enumerate(cols):
        parts.append(
            f'<text x="{width-right+10}" y="{top + 18 * idx}" font-size="11" fill="{colors[idx % len(colors)]}">{col}</text>'
        )
    (outdir / "verifier_breakdown_stacked.svg").write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">\n'
        + "\n".join(parts)
        + "\n</svg>\n",
        encoding="utf-8",
    )


def write_summary_rows(rows, outdir, metrics):
    lines = ["# SYMBT3 Scaling Summary\n"]
    for metric in metrics:
        if rows and metric in rows[0]:
            slope = fit_loglog_slope_rows(rows, metric)
            lines.append(f"- `{metric}` log-log slope: `{slope:.4f}`")
    bad = []
    sorted_rows = sorted(rows, key=lambda row: row["k"])
    for prev, cur in zip(sorted_rows, sorted_rows[1:]):
        if cur["k"] == 2 * prev["k"] and prev.get("oracle_len", 0) > 0:
            ratio = cur["oracle_len"] / prev["oracle_len"]
            if ratio > 2.0:
                bad.append((int(cur["k"]), ratio))
    if bad:
        lines.append("\n## Oracle growth violations")
        for k, ratio in bad:
            lines.append(f"- k={k}: oracle_len ratio {ratio:.3f} > 2")
    else:
        lines.append("\n- Oracle growth gate passed: no doubling ratio above 2.")
    (outdir / "summary.md").write_text("\n".join(lines), encoding="utf-8")


def _pgf_number(value):
    if isinstance(value, int):
        return str(value)
    return f"{float(value):.6g}"


def write_pgf_multi_series(rows, outdir, filename, series, ylabel, logy=False):
    rows = sorted(rows, key=lambda row: row["k"])
    valid_series = [
        (metric, legend)
        for metric, legend in series
        if rows and metric in rows[0]
    ]
    if not valid_series:
        return

    axis_options = [
        r"width=\linewidth",
        r"height=0.55\linewidth",
        r"grid=both",
        r"xmode=log",
        r"log basis x=2",
        r"xtick=data",
        r"xlabel={$k$}",
        rf"ylabel={{{ylabel}}}",
        r"legend style={at={(0.5,-0.22)},anchor=north,legend columns=2}",
    ]
    if logy:
        axis_options.extend([r"ymode=log", r"log basis y=10"])

    lines = [
        r"\begin{tikzpicture}",
        r"\begin{axis}[",
        "  " + ",\n  ".join(axis_options),
        r"]",
    ]
    for metric, legend in valid_series:
        points = []
        for row in rows:
            value = row.get(metric)
            if value is None or value != value:
                continue
            if logy and value <= 0:
                continue
            points.append(f"({_pgf_number(row['k'])},{_pgf_number(value)})")
        if not points:
            continue
        lines.append(r"\addplot+[mark=*] coordinates {" + " ".join(points) + "};")
        lines.append(rf"\addlegendentry{{{legend}}}")
    lines.extend([r"\end{axis}", r"\end{tikzpicture}", ""])
    (outdir / filename).write_text("\n".join(lines), encoding="utf-8")


def _coordinates(rows, metric):
    points = []
    for row in sorted(rows, key=lambda candidate: candidate["k"]):
        value = row.get(metric)
        if value is None or value != value or value <= 0:
            continue
        points.append(f"({_pgf_number(row['k'])},{_pgf_number(value)})")
    return " ".join(points)


def write_combined_time_plot(product_csv, k6a_csv, n8_csv, outdir):
    product_rows = sorted(load_rows(product_csv), key=lambda row: row["k"])
    k6a_rows = sorted(load_rows(k6a_csv), key=lambda row: row["k"])
    n8_rows = [
        row
        for row in sorted(load_rows(n8_csv), key=lambda row: row["k"])
        if row.get("status") == "OK"
    ]

    series = [
        (product_rows, "monolithic_verify_ms", "Product verify", "blue", "solid", "*"),
        (product_rows, "monolithic_prove_ms", "Product prove", "blue", "dashed", "square*"),
        (k6a_rows, "verify_ms", "K6a verify", "teal", "solid", "*"),
        (k6a_rows, "prove_ms", "K6a prove", "teal", "dashed", "square*"),
        (n8_rows, "verify_ms", "N8 verify", "orange", "solid", "*"),
        (n8_rows, "prove_ms", "N8 prove", "orange", "dashed", "square*"),
    ]

    lines = [
        r"\begin{tikzpicture}",
        r"\begin{axis}[",
        r"  width=\linewidth,",
        r"  height=0.62\linewidth,",
        r"  grid=both,",
        r"  xmode=log,",
        r"  log basis x=2,",
        r"  ymode=log,",
        r"  log basis y=10,",
        r"  xtick={1,2,4,8,16,32,64},",
        r"  xlabel={$k$},",
        r"  ylabel={time (ms)},",
        r"  legend style={at={(0.5,-0.22)},anchor=north,legend columns=3}",
        r"]",
    ]
    for rows, metric, legend, color, style, marker in series:
        coordinates = _coordinates(rows, metric)
        if not coordinates:
            continue
        lines.append(
            rf"\addplot+[mark={marker}, thick, color={color}, {style}] coordinates {{{coordinates}}};"
        )
        lines.append(rf"\addlegendentry{{{legend}}}")
    lines.extend([r"\end{axis}", r"\end{tikzpicture}", ""])

    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "all_route_times_vs_k.tex").write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote combined route timing PGF plot to {outdir}")


def fallback_product_route_main(csv_path, outdir):
    rows = sorted(load_rows(csv_path), key=lambda row: row["k"])
    write_pgf_multi_series(
        rows,
        outdir,
        "verify_ms_comparison.tex",
        [
            ("monolithic_verify_ms", "Product verify"),
            ("symbt3_verify_ms", "K6a verify"),
        ],
        "verifier time (ms)",
        logy=True,
    )
    write_pgf_multi_series(
        rows,
        outdir,
        "prove_ms_comparison.tex",
        [
            ("monolithic_prove_ms", "Product prove"),
            ("symbt3_prove_ms", "K6a prove"),
        ],
        "prover time (ms)",
        logy=True,
    )
    write_pgf_multi_series(
        rows,
        outdir,
        "proof_bytes_comparison.tex",
        [
            ("monolithic_proof_bytes", "Product proof"),
            ("symbt3_proof_bytes", "K6a proof"),
        ],
        "proof bytes",
        logy=True,
    )
    write_pgf_multi_series(
        rows,
        outdir,
        "speedup_vs_k.tex",
        [
            ("verify_speedup", "verify speedup"),
            ("prove_speedup", "prove speedup"),
        ],
        "baseline / K6a",
    )
    print(f"Wrote product-route PGF plots to {outdir}")


def fallback_n8_main(csv_path, outdir):
    rows = [
        row
        for row in sorted(load_rows(csv_path), key=lambda row: row["k"])
        if row.get("status") == "OK"
    ]
    write_pgf_multi_series(
        rows,
        outdir,
        "n8_time_vs_k.tex",
        [("prove_ms", "N8 prove"), ("verify_ms", "N8 verify")],
        "time (ms)",
    )
    write_pgf_multi_series(
        rows,
        outdir,
        "n8_proof_bytes_vs_k.tex",
        [("proof_bytes", "N8 proof"), ("public_statement_bytes", "public statement")],
        "bytes",
        logy=True,
    )
    print(f"Wrote N8 PGF plots to {outdir}")


def fallback_main(csv_path, outdir):
    rows = sorted(load_rows(csv_path), key=lambda row: row["k"])
    metrics = [
        "verify_ms",
        "prove_ms",
        "proof_bytes",
        "public_statement_bytes",
        "oracle_len",
        "whir_num_vars",
        "opened_field_elements",
        "sumcheck_rounds",
        "transcript_squeezes",
        "pcs_merkle_opening_proxy",
        "source_r1cs_residual_claims",
        "folded_gr1cs_boundary_claims",
        "folded_gr1cs_product_claims",
        "manifest_coordinate_count",
        "message_coordinate_count",
        "message_to_trace_binding_count",
    ]
    for metric in metrics:
        write_svg_line(rows, outdir, metric)
        if metric in {"verify_ms", "prove_ms", "proof_bytes", "oracle_len"}:
            write_svg_line(rows, outdir, metric, logy=True)
    write_svg_ratios(
        rows,
        outdir,
        ["verify_ms", "prove_ms", "proof_bytes", "oracle_len", "public_statement_bytes"],
    )
    write_svg_verifier_breakdown(rows, outdir)
    write_svg_guardrails(rows, outdir)
    write_summary_rows(rows, outdir, metrics)
    write_pgf_multi_series(
        rows,
        outdir,
        "k6a_time_vs_k.tex",
        [("prove_ms", "K6a prove"), ("verify_ms", "K6a verify")],
        "time (ms)",
    )
    write_pgf_multi_series(
        rows,
        outdir,
        "k6a_size_vs_k.tex",
        [("proof_bytes", "K6a proof"), ("public_statement_bytes", "public statement")],
        "bytes",
        logy=True,
    )
    write_pgf_multi_series(
        rows,
        outdir,
        "k6a_guardrails.tex",
        [
            ("top_level_whir_proof_count", "top-level WHIR proofs"),
            ("family_columnar_subproof_count", "family subproofs"),
            ("backend_table_count", "backend tables"),
        ],
        "count",
    )
    print(f"Wrote dependency-free SVG plots to {outdir}")


def require_cols(df, cols):
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")


def fit_loglog_slope(df, metric):
    sub = df[["k", metric]].dropna()
    sub = sub[(sub["k"] > 0) & (sub[metric] > 0)]
    if len(sub) < 2:
        return float("nan")

    xs = sub["k"].map(lambda x: math.log2(float(x))).to_list()
    ys = sub[metric].map(lambda y: math.log2(float(y))).to_list()

    xbar = sum(xs) / len(xs)
    ybar = sum(ys) / len(ys)
    num = sum((x - xbar) * (y - ybar) for x, y in zip(xs, ys))
    den = sum((x - xbar) ** 2 for x in xs)
    return num / den if den else float("nan")


def plot_metric(df, outdir, metric, ylabel=None, logy=False):
    if metric not in df.columns:
        return

    fig = plt.figure()
    plt.plot(df["k"], df[metric], marker="o")
    plt.xscale("log", base=2)
    if logy:
        plt.yscale("log", base=2)

    slope = fit_loglog_slope(df, metric)
    title = f"{metric} vs k"
    if not math.isnan(slope):
        title += f" | log-log slope ~= {slope:.3f}"

    plt.title(title)
    plt.xlabel("k")
    plt.ylabel(ylabel or metric)
    plt.grid(True, which="both")
    plt.tight_layout()

    suffix = "_loglog" if logy else ""
    fig.savefig(outdir / f"{metric}{suffix}.png", dpi=180)
    plt.close(fig)


def plot_ratios(df, outdir, metrics):
    rows = []
    df = df.sort_values("k").reset_index(drop=True)

    for i in range(1, len(df)):
        prev = df.iloc[i - 1]
        cur = df.iloc[i]
        if cur["k"] != 2 * prev["k"]:
            continue

        row = {"k": cur["k"]}
        for metric in metrics:
            if metric in df.columns and prev[metric] and prev[metric] > 0:
                row[f"{metric}_ratio"] = cur[metric] / prev[metric]
        rows.append(row)

    if not rows:
        return

    rdf = pd.DataFrame(rows)

    fig = plt.figure()
    for col in rdf.columns:
        if col == "k":
            continue
        plt.plot(rdf["k"], rdf[col], marker="o", label=col)

    plt.axhline(1.0, linestyle="--")
    plt.axhline(2.0, linestyle="--")
    plt.xscale("log", base=2)
    plt.title("Doubling ratios: metric(k) / metric(k/2)")
    plt.xlabel("k")
    plt.ylabel("ratio")
    plt.grid(True, which="both")
    plt.legend()
    plt.tight_layout()
    fig.savefig(outdir / "doubling_ratios.png", dpi=180)
    plt.close(fig)

    rdf.to_csv(outdir / "doubling_ratios.csv", index=False)


def plot_verifier_breakdown(df, outdir):
    cols = [
        "verify_whir_pcs_ms",
        "verify_transcript_ms",
        "verify_sumcheck_rounds_ms",
        "verify_final_constraint_eval_ms",
        "verify_final_eval_manifest_ms",
        "verify_final_eval_source_r1cs_ms",
        "verify_final_eval_folded_boundary_ms",
        "verify_final_eval_product_residual_ms",
        "verify_final_eval_ajtai_ms",
        "verify_final_eval_range_ms",
        "verify_final_eval_message_view_ms",
        "verify_manifest_membership_eval_ms",
        "verify_message_view_eval_ms",
        "verify_projection_eval_ms",
        "verify_monomial_embedding_eval_ms",
        "verify_representative_eval_ms",
        "verify_ajtai_eval_ms",
    ]
    present = [c for c in cols if c in df.columns]
    if not present:
        return

    fig = plt.figure(figsize=(11, 6))
    bottom = [0.0] * len(df)

    for col in present:
        values = df[col].fillna(0.0).to_list()
        plt.bar(df["k"].astype(str), values, bottom=bottom, label=col)
        bottom = [b + v for b, v in zip(bottom, values)]

    plt.title("Verifier time breakdown")
    plt.xlabel("k")
    plt.ylabel("ms")
    plt.legend(fontsize=7)
    plt.tight_layout()
    fig.savefig(outdir / "verifier_breakdown_stacked.png", dpi=180)
    plt.close(fig)


def plot_guardrails(df, outdir):
    guard_cols = [
        "top_level_whir_proof_count",
        "family_columnar_subproof_count",
        "backend_table_count",
        "message_to_trace_binding_count",
    ]
    present = [c for c in guard_cols if c in df.columns]
    if not present:
        return

    fig = plt.figure()
    for col in present:
        plt.plot(df["k"], df[col], marker="o", label=col)

    plt.xscale("log", base=2)
    plt.title("Architecture guardrails")
    plt.xlabel("k")
    plt.ylabel("count")
    plt.grid(True, which="both")
    plt.legend()
    plt.tight_layout()
    fig.savefig(outdir / "architecture_guardrails.png", dpi=180)
    plt.close(fig)


def write_summary(df, outdir, metrics):
    lines = ["# SYMBT3 Scaling Summary\n"]

    for metric in metrics:
        if metric not in df.columns:
            continue
        slope = fit_loglog_slope(df, metric)
        lines.append(f"- `{metric}` log-log slope: `{slope:.4f}`")

    if "oracle_len" in df.columns:
        df_sorted = df.sort_values("k")
        bad = []
        for i in range(1, len(df_sorted)):
            prev = df_sorted.iloc[i - 1]
            cur = df_sorted.iloc[i]
            if cur["k"] == 2 * prev["k"] and prev["oracle_len"] > 0:
                ratio = cur["oracle_len"] / prev["oracle_len"]
                if ratio > 2.0:
                    bad.append((int(cur["k"]), ratio))
        if bad:
            lines.append("\n## Oracle growth violations")
            for k, ratio in bad:
                lines.append(f"- k={k}: oracle_len ratio {ratio:.3f} > 2")
        else:
            lines.append("\n- Oracle growth gate passed: no doubling ratio above 2.")

    (outdir / "summary.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: plot_symbt3_scaling.py <symbt3_scaling.csv> [outdir]\n"
            "       plot_symbt3_scaling.py --combined-times <product.csv> <k6a.csv> <n8.csv> <outdir>"
        )
        sys.exit(1)

    if sys.argv[1] == "--combined-times":
        if len(sys.argv) != 6:
            print(
                "Usage: plot_symbt3_scaling.py --combined-times <product.csv> <k6a.csv> <n8.csv> <outdir>"
            )
            sys.exit(1)
        write_combined_time_plot(
            Path(sys.argv[2]),
            Path(sys.argv[3]),
            Path(sys.argv[4]),
            Path(sys.argv[5]),
        )
        return

    csv_path = Path(sys.argv[1])
    outdir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("plots/symbt3")
    outdir.mkdir(parents=True, exist_ok=True)

    rows = load_rows(csv_path)
    if rows and "monolithic_verify_ms" in rows[0] and "symbt3_verify_ms" in rows[0]:
        fallback_product_route_main(csv_path, outdir)
        return
    if rows and "semantic_mode" in rows[0] and "whir_instance_count" in rows[0]:
        fallback_n8_main(csv_path, outdir)
        return

    if not HAVE_PLOT_LIBS:
        fallback_main(csv_path, outdir)
        return

    df = pd.read_csv(csv_path)
    require_cols(df, ["k"])
    df = df.sort_values("k").reset_index(drop=True)

    metrics = [
        "verify_ms",
        "prove_ms",
        "proof_bytes",
        "public_statement_bytes",
        "oracle_len",
        "whir_num_vars",
        "opened_field_elements",
        "sumcheck_rounds",
        "transcript_squeezes",
        "pcs_merkle_opening_proxy",
        "source_r1cs_residual_claims",
        "folded_gr1cs_boundary_claims",
        "folded_gr1cs_product_claims",
        "manifest_coordinate_count",
        "message_coordinate_count",
        "message_to_trace_binding_count",
    ]

    for metric in metrics:
        plot_metric(df, outdir, metric)
        if metric in {"verify_ms", "prove_ms", "proof_bytes", "oracle_len"}:
            plot_metric(df, outdir, metric, logy=True)

    plot_ratios(
        df,
        outdir,
        ["verify_ms", "prove_ms", "proof_bytes", "oracle_len", "public_statement_bytes"],
    )
    plot_verifier_breakdown(df, outdir)
    plot_guardrails(df, outdir)
    write_summary(df, outdir, metrics)

    print(f"Wrote plots to {outdir}")


if __name__ == "__main__":
    main()
