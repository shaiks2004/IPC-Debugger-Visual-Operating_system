from __future__ import annotations

import csv
import json
import time
import tracemalloc
from pathlib import Path

from .plugins import list_plugins, get_plugin
from .scenario import IPCScenario


try:
    import matplotlib.pyplot as plt
except Exception:  # pragma: no cover - optional in runtime
    plt = None


def _single_run(plugin_name: str, key, scenario: IPCScenario) -> dict:
    plugin = get_plugin(plugin_name)
    tracemalloc.start()
    cpu_start = time.process_time()
    t0 = time.perf_counter()
    _, events = plugin.run(key=key, scenario=scenario)
    elapsed = time.perf_counter() - t0
    cpu_elapsed = time.process_time() - cpu_start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    messages = max(scenario.message_count, 1)
    return {
        "backend": plugin_name,
        "latency_sec": elapsed,
        "throughput_msg_per_sec": messages / elapsed if elapsed > 0 else 0.0,
        "cpu_sec": cpu_elapsed,
        "peak_memory_bytes": peak,
        "events": len(events),
    }


def run_benchmarks(scenario: IPCScenario, key=None, rounds: int = 3) -> list[dict]:
    rows: list[dict] = []
    for backend in list_plugins():
        for _ in range(rounds):
            rows.append(_single_run(backend, key, scenario))
    return rows


def export_benchmarks(rows: list[dict], out_dir: str | Path) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "benchmark_results.json"
    csv_path = out / "benchmark_results.csv"

    json_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["backend"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    plot_path = None
    if rows and plt is not None:
        latest_by_backend = {}
        for row in rows:
            latest_by_backend[row["backend"]] = row
        names = list(latest_by_backend.keys())
        latencies = [latest_by_backend[n]["latency_sec"] for n in names]
        throughputs = [latest_by_backend[n]["throughput_msg_per_sec"] for n in names]

        fig, ax = plt.subplots(1, 2, figsize=(10, 4))
        ax[0].bar(names, latencies)
        ax[0].set_title("Latency (sec)")
        ax[1].bar(names, throughputs)
        ax[1].set_title("Throughput (msg/sec)")
        fig.tight_layout()
        plot_path = out / "benchmark_plot.png"
        fig.savefig(plot_path)
        plt.close(fig)

    return {
        "json": str(json_path),
        "csv": str(csv_path),
        "plot": str(plot_path) if plot_path else "",
    }
