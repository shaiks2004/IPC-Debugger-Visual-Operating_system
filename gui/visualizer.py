from __future__ import annotations

import threading
import time
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

from modules.benchmark import export_benchmarks, run_benchmarks
from modules.education import LESSONS
from modules.learning_lab import (
    DEBUG_MISSIONS,
    LEARNING_PATHS,
    LESSON_GUIDES,
    QUIZ_BANK,
    apply_lesson_to_scenario,
    apply_mission_to_scenario,
    build_backend_comparison_summary,
    build_cause_effect_trace,
    build_student_report,
    export_student_report,
    grade_quiz,
    score_debug_mission,
)
from modules.msg_queue_comm import secure_message_queue_example
from modules.pipe_comm import secure_pipe_example
from modules.plugins import get_plugin
from modules.process_simulation import process_info
from modules.replay import ReplayRecorder, replay_stepwise
from modules.scenario import IPCScenario
from modules.security_posture import evaluate_security_posture
from modules.shared_memory_comm import secure_shared_memory_example
from modules.secure_utils import derive_key_from_password


class IPCVisualizer:
    def __init__(self, root):
        self.root = root
        self.user_key = None
        self.recorder = ReplayRecorder()
        self.last_events: list[dict] = []
        self.scenario_vars = {}
        self.current_backend = "pipe"
        self.active_mission_id = ""
        self.mission_start_ts = 0.0
        self.hints_used = 0
        self.quiz_results: list[dict] = []
        self.last_mission_score = None
        self.setup_ui()
        self._ask_passphrase()

    def _ask_passphrase(self):
        pwd = simpledialog.askstring(
            "Passphrase",
            "Enter passphrase to derive key (leave blank to generate):",
            show="*",
            parent=self.root,
        )
        if not pwd:
            self.user_key = None
            self.log("No passphrase entered: using generated keys.")
            return
        key, _salt = derive_key_from_password(pwd)
        self.user_key = key
        self.log("Passphrase accepted. Key derived for session.")

    def setup_ui(self):
        self.root.title("IPC Learning Lab: Debugger & Visual Operating System")

        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=8, pady=8)

        ttk.Label(top, text="IPC Learning Lab", font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Button(top, text="Start Here", command=self.start_here).pack(side="left", padx=4)
        ttk.Button(top, text="Run Pipe", command=self.run_pipe).pack(side="left", padx=4)
        ttk.Button(top, text="Run Queue", command=self.run_msg_queue).pack(side="left", padx=4)
        ttk.Button(top, text="Run Shared", command=self.run_shared_memory).pack(side="left", padx=4)
        ttk.Button(top, text="Compare Backends", command=self.run_compare_backends).pack(side="left", padx=4)
        ttk.Button(top, text="Run Process Sim", command=self.run_process_sim).pack(side="left", padx=4)
        ttk.Button(top, text="Benchmark", command=self.run_benchmark).pack(side="left", padx=4)
        ttk.Button(top, text="Export Student Report", command=self.export_lab_report).pack(side="left", padx=4)

        body = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        body.pack(fill="both", expand=True)

        left = ttk.Frame(body)
        right = ttk.Frame(body)
        body.add(left, weight=1)
        body.add(right, weight=2)

        self._build_scenario_panel(left)
        self._build_right_panel(right)

    def _build_scenario_panel(self, parent):
        lf = ttk.LabelFrame(parent, text="Scenario Builder / Lab Mode")
        lf.pack(fill="both", expand=True, padx=8, pady=6)

        defaults = IPCScenario()
        fields = [
            ("name", defaults.name),
            ("producers", defaults.producers),
            ("consumers", defaults.consumers),
            ("message_count", defaults.message_count),
            ("message_size", defaults.message_size),
            ("interval_ms", defaults.interval_ms),
        ]

        for i, (k, v) in enumerate(fields):
            ttk.Label(lf, text=k).grid(row=i, column=0, sticky="w", padx=4, pady=2)
            var = tk.StringVar(value=str(v))
            ttk.Entry(lf, textvariable=var, width=20).grid(row=i, column=1, sticky="ew", padx=4, pady=2)
            self.scenario_vars[k] = var

        toggles = [
            "tamper_ciphertext",
            "replay_attack",
            "key_mismatch",
            "drop_packet",
            "race_condition",
        ]
        start = len(fields)
        for i, k in enumerate(toggles):
            var = tk.BooleanVar(value=False)
            ttk.Checkbutton(lf, text=k, variable=var).grid(row=start + i, column=0, columnspan=2, sticky="w", padx=4)
            self.scenario_vars[k] = var

        ttk.Button(lf, text="Save Scenario", command=self.save_scenario).grid(row=20, column=0, padx=4, pady=6, sticky="ew")
        ttk.Button(lf, text="Load Scenario", command=self.load_scenario).grid(row=20, column=1, padx=4, pady=6, sticky="ew")
        ttk.Button(lf, text="Replay Last Run", command=self.replay_last_run).grid(row=21, column=0, padx=4, pady=2, sticky="ew")
        ttk.Button(lf, text="Load Replay File", command=self.load_replay_file).grid(row=21, column=1, padx=4, pady=2, sticky="ew")

        learning = ttk.LabelFrame(parent, text="Learning Paths")
        learning.pack(fill="x", padx=8, pady=6)
        self.path_var = tk.StringVar(value="beginner")
        ttk.Combobox(learning, values=sorted(LEARNING_PATHS.keys()), textvariable=self.path_var, state="readonly").pack(fill="x", padx=4, pady=4)
        ttk.Button(learning, text="Show Path Outcomes", command=self.show_learning_path).pack(fill="x", padx=4, pady=2)

        edu = ttk.LabelFrame(parent, text="Interactive Lesson Mode")
        edu.pack(fill="x", padx=8, pady=6)
        self.lesson_var = tk.StringVar(value="hmac_failure")
        lesson_box = ttk.Combobox(edu, values=sorted(LESSONS.keys()), textvariable=self.lesson_var, state="readonly")
        lesson_box.pack(fill="x", padx=4, pady=4)
        lesson_box.bind("<<ComboboxSelected>>", lambda _e: self.show_lesson())
        ttk.Button(edu, text="Show Lesson", command=self.show_lesson).pack(fill="x", padx=4, pady=2)
        ttk.Button(edu, text="Apply Lesson Scenario", command=self.apply_selected_lesson).pack(fill="x", padx=4, pady=2)
        ttk.Button(edu, text="Take Lesson Quiz", command=self.take_lesson_quiz).pack(fill="x", padx=4, pady=2)

        self.lesson_text = scrolledtext.ScrolledText(edu, height=8)
        self.lesson_text.pack(fill="x", padx=4, pady=4)

        ttk.Label(edu, text="Checkpoint prediction (before run):").pack(anchor="w", padx=4)
        self.prediction_var = tk.StringVar()
        ttk.Entry(edu, textvariable=self.prediction_var).pack(fill="x", padx=4, pady=2)
        ttk.Button(edu, text="Save Prediction", command=self.save_prediction).pack(fill="x", padx=4, pady=2)

        mission = ttk.LabelFrame(parent, text="Challenge Mode: Debug Missions")
        mission.pack(fill="x", padx=8, pady=6)
        self.mission_var = tk.StringVar(value="integrity_breach")
        ttk.Combobox(mission, values=sorted(DEBUG_MISSIONS.keys()), textvariable=self.mission_var, state="readonly").pack(fill="x", padx=4, pady=4)
        ttk.Button(mission, text="Start Mission", command=self.start_mission).pack(fill="x", padx=4, pady=2)
        ttk.Button(mission, text="Use Hint", command=self.use_mission_hint).pack(fill="x", padx=4, pady=2)
        ttk.Button(mission, text="Finish + Score Mission", command=self.finish_mission).pack(fill="x", padx=4, pady=2)
        ttk.Button(mission, text="Take Mission Quiz", command=self.take_mission_quiz).pack(fill="x", padx=4, pady=2)

        sec = ttk.LabelFrame(parent, text="Security Posture")
        sec.pack(fill="both", expand=True, padx=8, pady=6)
        self.posture_text = scrolledtext.ScrolledText(sec, height=10)
        self.posture_text.pack(fill="both", expand=True, padx=4, pady=4)

    def _build_right_panel(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True, padx=8, pady=6)

        timeline_tab = ttk.Frame(nb)
        logs_tab = ttk.Frame(nb)
        compare_tab = ttk.Frame(nb)
        trace_tab = ttk.Frame(nb)
        nb.add(timeline_tab, text="Protocol Timeline")
        nb.add(logs_tab, text="Console")
        nb.add(compare_tab, text="Side-by-side Compare")
        nb.add(trace_tab, text="Cause→Effect Coach")

        cols = ("timestamp", "channel", "action", "sender", "receiver", "size", "hmac_ok", "replayed", "dropped", "note")
        self.timeline = ttk.Treeview(timeline_tab, columns=cols, show="headings", height=15)
        for c in cols:
            self.timeline.heading(c, text=c)
            self.timeline.column(c, width=120 if c != "note" else 220, anchor="w")
        self.timeline.pack(fill="both", expand=True)

        compare_cols = ("backend", "events", "auth_failures", "replays", "drops", "decrypt_errors", "findings")
        self.compare_tree = ttk.Treeview(compare_tab, columns=compare_cols, show="headings", height=12)
        for c in compare_cols:
            self.compare_tree.heading(c, text=c)
            self.compare_tree.column(c, width=130 if c != "findings" else 240, anchor="w")
        self.compare_tree.pack(fill="both", expand=True)

        self.trace_text = scrolledtext.ScrolledText(trace_tab, height=20)
        self.trace_text.pack(fill="both", expand=True)

        self.console = scrolledtext.ScrolledText(logs_tab, height=20, bg="#111", fg="#ddd", font=("Consolas", 10))
        self.console.pack(fill="both", expand=True)
        self.log("Ready. Start with 'Start Here' for guided IPC learning.")
        self.show_lesson()

    def log(self, text):
        self.console.insert(tk.END, text + "\n")
        self.console.see(tk.END)

    def _read_scenario(self) -> IPCScenario:
        try:
            return IPCScenario(
                name=self.scenario_vars["name"].get() or "default",
                producers=int(self.scenario_vars["producers"].get()),
                consumers=int(self.scenario_vars["consumers"].get()),
                message_count=max(1, int(self.scenario_vars["message_count"].get())),
                message_size=max(1, int(self.scenario_vars["message_size"].get())),
                interval_ms=max(0, int(self.scenario_vars["interval_ms"].get())),
                tamper_ciphertext=bool(self.scenario_vars["tamper_ciphertext"].get()),
                replay_attack=bool(self.scenario_vars["replay_attack"].get()),
                key_mismatch=bool(self.scenario_vars["key_mismatch"].get()),
                drop_packet=bool(self.scenario_vars["drop_packet"].get()),
                race_condition=bool(self.scenario_vars["race_condition"].get()),
            )
        except Exception as e:
            messagebox.showerror("Scenario Error", f"Invalid scenario input: {e}")
            return IPCScenario()

    def _set_scenario_vars(self, sc: IPCScenario):
        self.scenario_vars["name"].set(sc.name)
        self.scenario_vars["producers"].set(str(sc.producers))
        self.scenario_vars["consumers"].set(str(sc.consumers))
        self.scenario_vars["message_count"].set(str(sc.message_count))
        self.scenario_vars["message_size"].set(str(sc.message_size))
        self.scenario_vars["interval_ms"].set(str(sc.interval_ms))
        self.scenario_vars["tamper_ciphertext"].set(sc.tamper_ciphertext)
        self.scenario_vars["replay_attack"].set(sc.replay_attack)
        self.scenario_vars["key_mismatch"].set(sc.key_mismatch)
        self.scenario_vars["drop_packet"].set(sc.drop_packet)
        self.scenario_vars["race_condition"].set(sc.race_condition)

    def _fill_timeline(self, events: list[dict]):
        self.timeline.delete(*self.timeline.get_children())
        for ev in events:
            self.timeline.insert(
                "",
                "end",
                values=(
                    ev.get("timestamp", ""),
                    ev.get("channel", ""),
                    ev.get("action", ""),
                    ev.get("sender_pid", ""),
                    ev.get("receiver_pid", ""),
                    ev.get("payload_size", 0),
                    ev.get("hmac_ok", ""),
                    ev.get("replayed", False),
                    ev.get("dropped", False),
                    ev.get("note", ""),
                ),
            )

    def _show_posture(self, scenario: IPCScenario):
        posture = evaluate_security_posture(scenario)
        self.posture_text.delete("1.0", tk.END)
        for k, v in posture.items():
            self.posture_text.insert(tk.END, f"{k}: {v}\n")

    def _show_cause_effect(self, events: list[dict]):
        lines = build_cause_effect_trace(events)
        self.trace_text.delete("1.0", tk.END)
        for line in lines:
            self.trace_text.insert(tk.END, f"- {line}\n")

    def run_in_thread(self, fn, title, backend_name: str):
        scenario = self._read_scenario()
        self.current_backend = backend_name

        def worker():
            self.log(f"[{title}] Starting with scenario: {scenario.to_dict()}")
            try:
                result, events = fn(self.user_key, scenario)
                self.last_events = events
                self.recorder.clear()
                for ev in events:
                    self.recorder.record(ev)
                self.root.after(0, lambda: self._fill_timeline(events))
                self.root.after(0, lambda: self._show_posture(scenario))
                self.root.after(0, lambda: self._show_cause_effect(events))
                if isinstance(result, str):
                    for line in result.splitlines():
                        self.log(line)
            except Exception as e:
                self.log(f"[Error] {e}")
            finally:
                self.log(f"[{title}] Finished.\n")

        threading.Thread(target=worker, daemon=True).start()

    def run_pipe(self):
        self.run_in_thread(lambda k, s: secure_pipe_example(key=k, scenario=s), "Pipe Learning Run", "pipe")

    def run_msg_queue(self):
        self.run_in_thread(lambda k, s: secure_message_queue_example(key=k, scenario=s), "Queue Learning Run", "queue")

    def run_shared_memory(self):
        self.run_in_thread(lambda k, s: secure_shared_memory_example(key=k, scenario=s), "Shared Memory Learning Run", "shared_memory")

    def run_process_sim(self):
        txt = process_info("Demo Process")
        self.log(txt)

    def save_scenario(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        sc = self._read_scenario()
        sc.save(path)
        self.log(f"Scenario saved: {path}")

    def load_scenario(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path:
            return
        sc = IPCScenario.load(path)
        self._set_scenario_vars(sc)
        self.log(f"Scenario loaded: {path}")
        self._show_posture(sc)

    def replay_last_run(self):
        if not self.last_events:
            self.log("No events to replay.")
            return
        self.timeline.delete(*self.timeline.get_children())

        events_iter = replay_stepwise(self.last_events)

        def step():
            try:
                ev = next(events_iter)
                self._fill_timeline(self.timeline_events() + [ev])
                self.root.after(120, step)
            except StopIteration:
                self.log("Replay finished.")

        step()

    def timeline_events(self):
        rows = []
        for item in self.timeline.get_children():
            v = self.timeline.item(item, "values")
            rows.append(
                {
                    "timestamp": v[0],
                    "channel": v[1],
                    "action": v[2],
                    "sender_pid": v[3],
                    "receiver_pid": v[4],
                    "payload_size": v[5],
                    "hmac_ok": v[6],
                    "replayed": v[7],
                    "dropped": v[8],
                    "note": v[9],
                }
            )
        return rows

    def load_replay_file(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path:
            return
        events = self.recorder.load(path)
        self.last_events = events
        self._fill_timeline(events)
        self._show_cause_effect(events)
        self.log(f"Replay file loaded: {path}")

    def run_benchmark(self):
        scenario = self._read_scenario()

        def worker():
            self.log("[Benchmark] Running comparative backend benchmark...")
            rows = run_benchmarks(scenario=scenario, key=self.user_key, rounds=2)
            out_dir = Path("benchmarks")
            paths = export_benchmarks(rows, out_dir)
            for row in rows:
                self.log(str(row))
            self.log(f"[Benchmark] Exported: {paths}")

            replay_file = out_dir / "last_run_events.json"
            self.recorder.save(replay_file)
            self.log(f"[Replay] Saved events to {replay_file}")

        threading.Thread(target=worker, daemon=True).start()

    def run_compare_backends(self):
        scenario = self._read_scenario()

        def worker():
            self.log("[Compare] Running side-by-side backend comparison...")
            results: dict[str, tuple[str, list[dict]]] = {}
            for backend in ("pipe", "queue", "shared_memory"):
                plugin = get_plugin(backend)
                results[backend] = plugin.run(key=self.user_key, scenario=scenario)
            rows = build_backend_comparison_summary(results)

            def update_ui():
                self.compare_tree.delete(*self.compare_tree.get_children())
                for row in rows:
                    self.compare_tree.insert(
                        "",
                        "end",
                        values=(
                            row["backend"],
                            row["events"],
                            row["auth_failures"],
                            row["replays"],
                            row["drops"],
                            row["decrypt_errors"],
                            row["findings"],
                        ),
                    )

                merged_events: list[dict] = []
                for _backend, (_logs, evs) in results.items():
                    merged_events.extend(evs)
                self._show_cause_effect(merged_events)
                self.log("[Compare] Comparison table updated.")

            self.root.after(0, update_ui)

        threading.Thread(target=worker, daemon=True).start()

    def show_lesson(self):
        key = self.lesson_var.get()
        txt = LESSONS.get(key, "No lesson available.")
        guide = LESSON_GUIDES.get(key, {})
        lines = [
            f"Lesson: {key}",
            f"Goal: {guide.get('goal', txt)}",
            f"Observe: {guide.get('observe', 'Inspect timeline and security posture.')}",
            f"Success criteria: {guide.get('success_criteria', 'Explain findings clearly.')}",
            "Checkpoints:",
        ]
        for checkpoint in guide.get("checkpoints", []):
            lines.append(f"- {checkpoint}")
        text = "\n".join(lines)
        self.lesson_text.delete("1.0", tk.END)
        self.lesson_text.insert(tk.END, text)
        self.log(f"Lesson loaded ({key}).")

    def apply_selected_lesson(self):
        key = self.lesson_var.get()
        scenario = apply_lesson_to_scenario(self._read_scenario(), key)
        self._set_scenario_vars(scenario)
        self._show_posture(scenario)
        self.log(f"Applied lesson scenario for '{key}'.")

    def save_prediction(self):
        pred = self.prediction_var.get().strip()
        if not pred:
            messagebox.showinfo("Checkpoint", "Enter a prediction first.")
            return
        self.log(f"Checkpoint prediction saved: {pred}")

    def show_learning_path(self):
        path_key = self.path_var.get()
        path_data = LEARNING_PATHS.get(path_key)
        if not path_data:
            return
        lines = [f"Path: {path_data['title']}", "Outcomes:"]
        for out in path_data.get("outcomes", []):
            lines.append(f"- {out}")
        lines.append("Lessons:")
        for l in path_data.get("lessons", []):
            lines.append(f"- {l}")
        msg = "\n".join(lines)
        messagebox.showinfo("Learning Path", msg)
        self.log(f"Learning path shown: {path_key}")

    def start_here(self):
        self.path_var.set("beginner")
        self.lesson_var.set("hmac_failure")
        self.show_lesson()
        messagebox.showinfo(
            "Start Here",
            "Welcome to IPC Learning Lab!\n\n"
            "1) Review Beginner path outcomes\n"
            "2) Apply the HMAC Failure lesson scenario\n"
            "3) Save your checkpoint prediction\n"
            "4) Run Pipe, Queue, or Shared backend\n"
            "5) Inspect Timeline + Cause→Effect + Security Posture\n"
            "6) Take quiz and export your student report",
        )
        self.log("Start Here flow loaded: Beginner -> hmac_failure.")

    def start_mission(self):
        mission_id = self.mission_var.get()
        mission = DEBUG_MISSIONS.get(mission_id)
        if not mission:
            return
        scenario = apply_mission_to_scenario(self._read_scenario(), mission_id)
        self._set_scenario_vars(scenario)
        self.active_mission_id = mission_id
        self.mission_start_ts = time.perf_counter()
        self.hints_used = 0
        self.last_mission_score = None
        prompt = mission.get("prompt", "Run the scenario and diagnose the issue.")
        messagebox.showinfo(mission.get("title", "Mission"), prompt)
        self.log(f"Mission started: {mission_id}")

    def use_mission_hint(self):
        mission = DEBUG_MISSIONS.get(self.active_mission_id or self.mission_var.get())
        if not mission:
            messagebox.showinfo("Hint", "Start a mission first.")
            return
        hints = mission.get("hints", [])
        idx = min(self.hints_used, max(0, len(hints) - 1))
        hint = hints[idx] if hints else "No hints configured."
        self.hints_used += 1
        messagebox.showinfo("Mission Hint", hint)
        self.log(f"Mission hint used ({self.hints_used}): {hint}")

    def finish_mission(self):
        if not self.active_mission_id:
            messagebox.showinfo("Mission", "Start a mission first.")
            return
        if not self.last_events:
            messagebox.showinfo("Mission", "Run a backend to generate events before scoring.")
            return
        elapsed = max(0.0, time.perf_counter() - self.mission_start_ts)
        score = score_debug_mission(self.active_mission_id, self.last_events, elapsed, self.hints_used)
        self.last_mission_score = score
        msg = (
            f"Mission: {score.mission_id}\n"
            f"Total score: {score.total_score}/100\n"
            f"Correctness: {score.correctness_points}\n"
            f"Speed: {score.speed_points}\n"
            f"Hint penalty: -{score.hint_penalty}\n"
            f"Findings: {', '.join(score.findings) if score.findings else 'none'}"
        )
        messagebox.showinfo("Mission Result", msg)
        self.log(msg)

    def take_lesson_quiz(self):
        quiz_key = self.lesson_var.get()
        self._take_quiz(quiz_key)

    def take_mission_quiz(self):
        self._take_quiz("mission")

    def _take_quiz(self, quiz_key: str):
        quiz = QUIZ_BANK.get(quiz_key) or QUIZ_BANK["mission"]
        options = ", ".join(quiz["options"])
        answer = simpledialog.askstring("Quiz", f"{quiz['question']}\nOptions: {options}\n\nType exact option text:")
        if answer is None:
            return
        result = grade_quiz(quiz_key, answer)
        self.quiz_results.append({"quiz": quiz_key, "answer": answer, **result})
        messagebox.showinfo("Quiz Feedback", f"{result['feedback']}\n{result['explanation']}")
        self.log(f"Quiz ({quiz_key}): {result['feedback']}")

    def export_lab_report(self):
        if not self.last_events:
            messagebox.showinfo("Export", "Run at least one backend before exporting report.")
            return
        out = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")], initialfile="student_lab_report.json")
        if not out:
            return
        report = build_student_report(
            scenario=self._read_scenario(),
            backend=self.current_backend,
            events=self.last_events,
            mission_score=self.last_mission_score,
            quiz_results=self.quiz_results,
        )
        path = export_student_report(report, out)
        self.log(f"Student report exported: {path}")
        messagebox.showinfo("Export", f"Student report saved:\n{path}")
