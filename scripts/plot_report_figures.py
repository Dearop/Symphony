#!/usr/bin/env python3
"""Generate publication-style evaluation figures for the LaTeX report."""

from __future__ import annotations

import argparse
import csv
import math
import os
import sys
import tempfile
from pathlib import Path

MPL_CONFIG_DIR = Path(tempfile.gettempdir()) / "symphony_matplotlib"
MPL_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(MPL_CONFIG_DIR))

try:
    import matplotlib

    matplotlib.use("pdf")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter
except ModuleNotFoundError as err:
    print(
        "error: matplotlib is required to generate report PDF figures. "
        "Install matplotlib in the active Python environment and rerun this script.",
        file=sys.stderr,
    )
    raise SystemExit(2) from err


K_TICKS = [1, 2, 4, 8, 16, 32, 64]
K_POS = {k: math.log2(k) for k in K_TICKS}
ROUTE_STYLES = {
    "Product public verifier": {"color": "#4C78A8", "marker": "o", "linestyle": "-"},
    "K6a accumulator": {"color": "#F58518", "marker": "s", "linestyle": "--"},
    "N8 integrated": {"color": "#54A24B", "marker": "^", "linestyle": "-."},
}


def warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def to_number(value: str):
    if value == "":
        return None
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        as_float = float(value)
    except ValueError:
        return value
    if as_float.is_integer():
        return int(as_float)
    return as_float


def read_csv(path: Path | None) -> list[dict]:
    if path is None:
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return [
            {key: to_number(value) for key, value in row.items()}
            for row in csv.DictReader(handle)
        ]


def first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    warn("none of these files exist: " + ", ".join(str(path) for path in paths))
    return None


def metric_by_k(rows: list[dict], metric: str, *, only_ok: bool = False) -> dict[int, float]:
    values = {}
    for row in rows:
        if only_ok and row.get("status") != "OK":
            continue
        k = row.get("k")
        value = row.get(metric)
        if k in K_POS and isinstance(value, (int, float)) and value > 0:
            values[int(k)] = float(value)
    return dict(sorted(values.items()))


def merge_k6a(product_rows: list[dict], scaling_rows: list[dict], product_metric: str, scaling_metric: str) -> dict[int, float]:
    """Use product-comparison K6a rows first, then extend from the scaling CSV."""

    merged = metric_by_k(product_rows, product_metric)
    for k, value in metric_by_k(scaling_rows, scaling_metric).items():
        merged.setdefault(k, value)
    return dict(sorted(merged.items()))


def xy_from_series(series: dict[int, float]) -> tuple[list[float], list[float]]:
    ks = [k for k in K_TICKS if k in series]
    return [K_POS[k] for k in ks], [series[k] for k in ks]


def configure_matplotlib() -> None:
    plt.rcParams.update(
        {
            "figure.dpi": 160,
            "savefig.dpi": 300,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "font.family": "DejaVu Sans",
            "font.size": 9.5,
            "axes.labelsize": 10,
            "axes.titlesize": 10.5,
            "legend.fontsize": 8.5,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.color": "#D9D9D9",
            "grid.linewidth": 0.7,
            "grid.alpha": 0.8,
        }
    )


def format_plain(value: float, _pos=None) -> str:
    if value >= 1000:
        return f"{value:,.0f}"
    if value >= 100:
        return f"{value:.0f}"
    if value >= 10:
        return f"{value:.0f}"
    if value >= 1:
        return f"{value:g}"
    return f"{value:.1g}"


def style_axis(ax, ylabel: str, *, logy: bool = False) -> None:
    ax.set_xlim(K_POS[1] - 0.15, K_POS[64] + 0.15)
    ax.set_xticks([K_POS[k] for k in K_TICKS])
    ax.set_xticklabels([str(k) for k in K_TICKS])
    ax.set_xlabel("Accumulated arity k")
    ax.set_ylabel(ylabel)
    if logy:
        ax.set_yscale("log")
        ax.yaxis.set_major_formatter(FuncFormatter(format_plain))
    ax.grid(True, which="major", axis="both")
    if logy:
        ax.grid(True, which="minor", axis="y", alpha=0.25)


def plot_routes(ax, series_by_route: dict[str, dict[int, float]], *, linewidth: float = 2.0) -> None:
    for route, series in series_by_route.items():
        if not series:
            continue
        style = ROUTE_STYLES[route]
        xs, ys = xy_from_series(series)
        ax.plot(
            xs,
            ys,
            label=route,
            color=style["color"],
            marker=style["marker"],
            linestyle=style["linestyle"],
            linewidth=linewidth,
            markersize=5.2,
        )


def save_with_legend(fig, ax, path: Path, *, ncol: int = 3) -> None:
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.22),
        ncol=ncol,
        frameon=False,
        handlelength=2.6,
        columnspacing=1.5,
    )
    fig.subplots_adjust(bottom=0.28)
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {path}")


def plot_time_figure(path: Path, series_by_route: dict[str, dict[int, float]], ylabel: str, *, note: bool) -> None:
    fig, ax = plt.subplots(figsize=(6.4, 3.55))
    plot_routes(ax, series_by_route)
    style_axis(ax, ylabel, logy=True)
    if note:
        ax.text(
            0.03,
            0.95,
            "Product data stops at k=8\n(k=16 killed locally)",
            transform=ax.transAxes,
            va="top",
            ha="left",
            fontsize=8.3,
            bbox={"boxstyle": "round,pad=0.25", "facecolor": "white", "edgecolor": "#BDBDBD", "alpha": 0.94},
        )
    save_with_legend(fig, ax, path)


def plot_size_figure(path: Path, series_by_route: dict[str, dict[int, float]], ylabel: str, *, y_min: float | None = None) -> None:
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    plot_routes(ax, series_by_route)
    style_axis(ax, ylabel)
    if y_min is not None:
        _, ymax = ax.get_ylim()
        ax.set_ylim(y_min, ymax)
    save_with_legend(fig, ax, path)


def plot_n8_timer_breakdown(path: Path, timer_rows: list[dict]) -> None:
    by_k = {int(row["k"]): row for row in timer_rows if row.get("status") == "OK" and row.get("k") in {1, 8, 64}}
    ks = [k for k in [1, 8, 64] if k in by_k]
    if not ks:
        warn("n8 timer CSV did not contain OK rows for k=1,8,64; skipping eval_n8_timer_breakdown.pdf")
        return

    prover_components = [
        ("direct_semantic_input_total_ms", "Semantic input", "#4C78A8"),
        ("whir_prove_ms", "WHIR prove", "#F58518"),
        ("serialization_ms", "Serialization", "#9D755D"),
    ]
    verifier_components = [
        ("whir_verify_ms", "WHIR verify", "#54A24B"),
        ("query_opening_verify_ms", "Query openings", "#E45756"),
        ("authority_gate_ms", "Authority gate", "#B279A2"),
    ]

    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.25), sharex=False)
    for ax, components, title in [
        (axes[0], prover_components, "Prover-side components"),
        (axes[1], verifier_components, "Verifier-side components"),
    ]:
        bottoms = [0.0] * len(ks)
        x_positions = list(range(len(ks)))
        for metric, label, color in components:
            values = [float(by_k[k].get(metric) or 0.0) for k in ks]
            ax.bar(x_positions, values, bottom=bottoms, color=color, label=label, width=0.62)
            bottoms = [bottom + value for bottom, value in zip(bottoms, values)]
        ax.set_title(title)
        ax.set_xticks(x_positions)
        ax.set_xticklabels([str(k) for k in ks])
        ax.set_xlabel("Accumulated arity k")
        ax.set_ylabel("Time (ms)")
        ax.yaxis.set_major_formatter(FuncFormatter(format_plain))
        ax.grid(True, axis="y")

    handles, labels = [], []
    for ax in axes:
        ax_handles, ax_labels = ax.get_legend_handles_labels()
        handles.extend(ax_handles)
        labels.extend(ax_labels)
    fig.legend(
        handles,
        labels,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.02),
        ncol=3,
        frameon=False,
        columnspacing=1.3,
    )
    fig.subplots_adjust(bottom=0.25, wspace=0.35)
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {path}")


def build_figures(repo_root: Path) -> None:
    configure_matplotlib()

    benchmarks = repo_root / "benchmarks"
    figures = repo_root / "report" / "figures"
    figures.mkdir(parents=True, exist_ok=True)

    product_path = first_existing(
        [
            benchmarks / "product_route_comparison.csv",
            benchmarks / "product_route_comparison_k1_8.csv",
        ]
    )
    k6a_path = first_existing([benchmarks / "symbt3_scaling.csv"])
    n8_path = first_existing(
        [
            benchmarks / "n8_integrated_authority.csv",
            repo_root / "n8_integrated_authority.csv",
        ]
    )
    timer_path = first_existing(
        [
            benchmarks / "n8_integrated_timer.csv",
            repo_root / "n8_integrated_timer.csv",
        ]
    )

    product_rows = read_csv(product_path)
    k6a_rows = read_csv(k6a_path)
    n8_rows = read_csv(n8_path)
    timer_rows = read_csv(timer_path)

    if product_rows:
        product_max_k = max(int(row["k"]) for row in product_rows if row.get("k") in K_POS)
        if product_max_k > 8:
            warn(f"product CSV contains rows beyond k=8 (max k={product_max_k}); plotting available rows without extrapolation")

    verify_series = {
        "Product public verifier": metric_by_k(product_rows, "monolithic_verify_ms"),
        "K6a accumulator": metric_by_k(k6a_rows, "verify_ms"),
        "N8 integrated": metric_by_k(n8_rows, "verify_ms", only_ok=True),
    }
    plot_time_figure(
        figures / "eval_verify_time.pdf",
        verify_series,
        "Verifier time (ms)",
        note=bool(verify_series["Product public verifier"]),
    )

    prove_series = {
        "Product public verifier": metric_by_k(product_rows, "monolithic_prove_ms"),
        "K6a accumulator": merge_k6a(product_rows, k6a_rows, "symbt3_prove_ms", "prove_ms"),
        "N8 integrated": metric_by_k(n8_rows, "prove_ms", only_ok=True),
    }
    plot_time_figure(
        figures / "eval_prove_time.pdf",
        prove_series,
        "Prover time (ms)",
        note=bool(prove_series["Product public verifier"]),
    )

    proof_series = {
        "Product public verifier": {
            k: value / (1024.0 * 1024.0)
            for k, value in metric_by_k(product_rows, "monolithic_proof_bytes").items()
        },
        "K6a accumulator": {
            k: value / (1024.0 * 1024.0)
            for k, value in merge_k6a(product_rows, k6a_rows, "symbt3_proof_bytes", "proof_bytes").items()
        },
        "N8 integrated": {
            k: value / (1024.0 * 1024.0)
            for k, value in metric_by_k(n8_rows, "proof_bytes", only_ok=True).items()
        },
    }
    plot_size_figure(figures / "eval_proof_size.pdf", proof_series, "Serialized proof size (MiB)", y_min=0.0)

    public_series = {
        "Product public verifier": {
            k: value / 1024.0
            for k, value in metric_by_k(product_rows, "monolithic_public_statement_bytes").items()
        },
        "K6a accumulator": {
            k: value / 1024.0
            for k, value in merge_k6a(
                product_rows,
                k6a_rows,
                "symbt3_public_statement_bytes",
                "public_statement_bytes",
            ).items()
        },
        "N8 integrated": {
            k: value / 1024.0
            for k, value in metric_by_k(n8_rows, "public_statement_bytes", only_ok=True).items()
        },
    }
    plot_size_figure(figures / "eval_public_statement_size.pdf", public_series, "Public statement size (KiB)")

    if timer_rows:
        plot_n8_timer_breakdown(figures / "eval_n8_timer_breakdown.pdf", timer_rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root. Defaults to the parent of scripts/.",
    )
    args = parser.parse_args()
    build_figures(args.repo_root.resolve())


if __name__ == "__main__":
    main()
