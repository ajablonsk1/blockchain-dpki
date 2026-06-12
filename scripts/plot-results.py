#!/usr/bin/env python3
"""Generate the evaluation-chapter charts from benchmark JSON reports.

Usage:
    python3 scripts/plot-results.py results/<timestamp> [output-dir]

Reads throughput.json, latency.json, state.json and proof.json from the given
results directory and writes PNG + SVG charts (default output: the same
directory, charts/ subfolder).
"""

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

plt.rcParams.update({
    "figure.figsize": (7, 4.5),
    "figure.dpi": 150,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "font.size": 10,
})


def load(results_dir: Path, name: str):
    path = results_dir / name
    if not path.exists():
        print(f"skip: {path} not found")
        return None
    with open(path) as f:
        return json.load(f)


def save(fig, out_dir: Path, name: str):
    for ext in ("png", "svg"):
        target = out_dir / f"{name}.{ext}"
        fig.savefig(target, bbox_inches="tight")
        print(f"wrote {target}")
    plt.close(fig)


def plot_throughput(report, out_dir: Path):
    rows = report["throughput"]
    target = [r["target_tps"] for r in rows]
    actual = [r["actual_tps"] for r in rows]
    avg_block = [r["avg_block_txs"] for r in rows]

    fig, ax = plt.subplots()
    ax.plot(target, actual, "o-", label="osiągnięta przepustowość")
    ax.plot(target, target, "--", color="gray", alpha=0.6, label="ideał (y = x)")
    ax.set_xlabel("zadane tempo wysyłania [tx/s]")
    ax.set_ylabel("transakcje zatwierdzone w blokach [tx/s]")
    ax.set_title("Przepustowość: 4-walidatorowy testnet DPKI")
    ax.legend()
    save(fig, out_dir, "throughput")

    fig, ax = plt.subplots()
    ax.bar([str(t) for t in target], avg_block, color="tab:blue", alpha=0.8)
    ax.set_xlabel("zadane tempo wysyłania [tx/s]")
    ax.set_ylabel("średnia liczba tx w bloku")
    ax.set_title("Wypełnienie bloków pod obciążeniem")
    save(fig, out_dir, "block-fill")


def plot_latency(report, out_dir: Path):
    lat = report["latency"]
    samples = lat["samples_ms"]

    fig, ax = plt.subplots()
    ax.hist(samples, bins=30, color="tab:blue", alpha=0.8, edgecolor="white")
    for p, color in (("p50_ms", "tab:green"), ("p95_ms", "tab:orange"), ("p99_ms", "tab:red")):
        ax.axvline(lat[p], color=color, linestyle="--",
                   label=f"{p[:3]} = {lat[p]:.0f} ms")
    ax.set_xlabel("opóźnienie zatwierdzenia [ms]")
    ax.set_ylabel("liczba transakcji")
    ax.set_title(f"Opóźnienie od wysłania do bloku (n = {lat['txs']})")
    ax.legend()
    save(fig, out_dir, "latency")


def plot_state(report, out_dir: Path):
    rows = report["state"]
    n = [r["domains"] for r in rows]
    mb = [r["store_bytes"] / (1024 * 1024) for r in rows]
    insert_us = [r["avg_insert_us"] for r in rows]

    fig, ax = plt.subplots()
    ax.plot(n, mb, "o-", color="tab:blue", label="rozmiar stanu")
    ax.set_xlabel("liczba zarejestrowanych domen")
    ax.set_ylabel("rozmiar magazynu stanu [MB]")
    ax.set_title("Wzrost stanu: liniowy względem liczby domen")
    ax2 = ax.twinx()
    ax2.plot(n, insert_us, "s--", color="tab:orange", alpha=0.7, label="czas wstawienia")
    ax2.set_ylabel("średni czas wstawienia [µs]")
    ax2.grid(False)
    lines = ax.get_lines() + ax2.get_lines()
    ax.legend(lines, [ln.get_label() for ln in lines], loc="upper left")
    save(fig, out_dir, "state-growth")


def plot_proof(report, out_dir: Path):
    rows = report["proof"]
    n = [r["domains"] for r in rows]
    size = [r["avg_proof_bytes"] for r in rows]
    nonincl = [r["non_inclusion_avg_proof_bytes"] for r in rows]
    verify = [r["avg_verify_us"] for r in rows]

    fig, ax = plt.subplots()
    ax.semilogx(n, size, "o-", label="proof inkluzji")
    ax.semilogx(n, nonincl, "s--", label="proof nie-inkluzji")
    ax.set_xlabel("liczba domen w drzewie (skala log)")
    ax.set_ylabel("średni rozmiar proofa [B]")
    ax.set_title("Rozmiar proofa Merkle: O(log N)")
    ax.legend()
    save(fig, out_dir, "proof-size")

    fig, ax = plt.subplots()
    ax.semilogx(n, verify, "o-", color="tab:green")
    ax.set_xlabel("liczba domen w drzewie (skala log)")
    ax.set_ylabel("średni czas weryfikacji offline [µs]")
    ax.set_title("Czas weryfikacji proofa")
    save(fig, out_dir, "proof-verify-time")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    results_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else results_dir / "charts"
    out_dir.mkdir(parents=True, exist_ok=True)

    if (r := load(results_dir, "throughput.json")) is not None:
        plot_throughput(r, out_dir)
    if (r := load(results_dir, "latency.json")) is not None:
        plot_latency(r, out_dir)
    if (r := load(results_dir, "state.json")) is not None:
        plot_state(r, out_dir)
    if (r := load(results_dir, "proof.json")) is not None:
        plot_proof(r, out_dir)


if __name__ == "__main__":
    main()
