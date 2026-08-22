# IPC-Debugger-Visual-Operating_system

A secure IPC simulation and visualization toolkit for exploring process communication, attack scenarios, replayable protocol traces, and backend benchmarking.

## What this project now includes

- **Attack/Defense simulation mode** for:
  - tampered ciphertext
  - replay attack
  - key mismatch
  - dropped packets
  - race conditions
- **Protocol timeline + packet inspector** with per-event metadata:
  timestamps, channel, sender/receiver PID, payload size, HMAC status, replay/drop flags.
- **Comparative benchmarking** across Pipe, Queue, and Shared Memory backends with exports:
  - `benchmark_results.json`
  - `benchmark_results.csv`
  - `benchmark_plot.png` (if matplotlib is available)
- **Scenario builder / lab mode** with save/load JSON profiles.
- **Deterministic replay** support from in-memory runs or JSON replay files.
- **Security posture panel** summarizing confidentiality/integrity/authentication/replay/availability posture.
- **Educational mode** with guided security lessons.
- **Plugin architecture** for extensible IPC backends.
- **CLI entrypoint** for backend runs and benchmarks.
- **Pytest suite + CI** for baseline quality checks.

## Project structure

- `main.py` – desktop app entrypoint.
- `gui/visualizer.py` – Tkinter UI for simulation, inspection, replay, and benchmarking.
- `modules/secure_utils.py` – key derivation, encryption/decryption, HMAC helpers.
- `modules/scenario.py` – scenario data model + save/load.
- `modules/event_model.py` – protocol event schema.
- `modules/replay.py` – recorder + deterministic stepwise replay.
- `modules/security_posture.py` – posture evaluation from scenario toggles.
- `modules/education.py` – educational lesson content.
- `modules/plugins.py` – plugin registry for IPC backend runners.
- `modules/benchmark.py` – comparative benchmark and report export.
- `modules/pipe_comm.py` – secure pipe simulation backend.
- `modules/msg_queue_comm.py` – secure message queue simulation backend.
- `modules/shared_memory_comm.py` – secure shared memory simulation backend.
- `tests/` – pytest unit/integration tests.
- `.github/workflows/ci.yml` – CI workflow running tests.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run desktop UI

```bash
python main.py
```

## Run CLI

Run a single backend simulation:

```bash
python cli.py --backend pipe
```

Run comparative benchmarking:

```bash
python cli.py --benchmark --out benchmarks
```

Use a saved scenario:

```bash
python cli.py --backend queue --scenario /absolute/path/to/scenario.json
```

## Run tests

```bash
pytest -q
```
