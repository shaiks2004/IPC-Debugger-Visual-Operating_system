# IPC Learning Lab (IPC-Debugger-Visual-Operating_system)

A student-focused IPC debugger and visualization lab for learning process communication, security failures, and protocol debugging through guided lessons and challenge missions.

## What this project now includes

- **Structured learning paths** (Beginner → Intermediate → Security) with outcomes.
- **Interactive lessons** with:
  - Goal
  - What to observe
  - Success criteria
  - Guided checkpoints (prediction before run)
- **Challenge mode (Debug Missions)** with scoring based on correctness, speed, and hints used.
- **Protocol timeline + packet inspector** with per-event metadata:
  timestamps, channel, sender/receiver PID, payload size, HMAC status, replay/drop flags.
- **Cause→Effect coaching panel** explaining why integrity, replay, or decryption failures occurred.
- **Side-by-side backend comparison** for Pipe, Queue, and Shared Memory on the same scenario.
- **Assessment and feedback** via quizzes and instant explanations.
- **Instructor-ready student report export** including scenario, findings, score, rubric, and replay trace.
- **Comparative benchmarking** with exports:
  - `benchmark_results.json`
  - `benchmark_results.csv`
  - `benchmark_plot.png` (if matplotlib is available)
- **Scenario builder / lab mode** with save/load JSON profiles.
- **Deterministic replay** support from in-memory runs or JSON replay files.
- **Security posture panel** summarizing confidentiality/integrity/authentication/replay/availability posture.
- **Plugin architecture** for extensible IPC backends.
- **CLI entrypoint** for backend runs and benchmarks.
- **Pytest suite + CI** for baseline quality checks.

## Project structure

- `main.py` – desktop app entrypoint.
- `gui/visualizer.py` – Tkinter UI for learning paths, lessons, missions, replay, comparison, and benchmarking.
- `modules/learning_lab.py` – learning-path metadata, lessons, missions, quizzes, scoring, cause/effect traces, student report export.
- `modules/secure_utils.py` – key derivation, encryption/decryption, HMAC helpers.
- `modules/scenario.py` – scenario data model + save/load.
- `modules/event_model.py` – protocol event schema.
- `modules/replay.py` – recorder + deterministic stepwise replay.
- `modules/security_posture.py` – posture evaluation from scenario toggles.
- `modules/education.py` – educational lesson text.
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

### Recommended 2-minute onboarding

1. Click **Start Here**.
2. Review the **Beginner** path outcomes.
3. Apply the **hmac_failure** lesson scenario.
4. Save a prediction, run a backend, and inspect Timeline + Cause→Effect.
5. Take quiz and export student report.

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
