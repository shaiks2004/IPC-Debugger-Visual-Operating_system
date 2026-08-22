from __future__ import annotations

import argparse
from pathlib import Path

from modules.benchmark import run_benchmarks, export_benchmarks
from modules.plugins import list_plugins, get_plugin
from modules.scenario import IPCScenario


def main() -> None:
    parser = argparse.ArgumentParser(description="IPC Debugger CLI")
    parser.add_argument("--backend", choices=list_plugins(), default="pipe")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--scenario", type=str, default="")
    parser.add_argument("--out", type=str, default="benchmarks")
    args = parser.parse_args()

    scenario = IPCScenario.load(args.scenario) if args.scenario else IPCScenario()

    if args.benchmark:
        rows = run_benchmarks(scenario)
        paths = export_benchmarks(rows, Path(args.out))
        print("Benchmark complete:", paths)
        return

    plugin = get_plugin(args.backend)
    logs, _ = plugin.run(scenario=scenario)
    print(logs)


if __name__ == "__main__":
    main()
