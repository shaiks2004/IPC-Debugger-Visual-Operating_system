from __future__ import annotations

import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

from modules.benchmark import export_benchmarks, run_benchmarks
from modules.education import LESSONS
from modules.msg_queue_comm import secure_message_queue_example
from modules.pipe_comm import secure_pipe_example
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
        self.root.title("Secure IPC Framework & Visualizer")

        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=8, pady=8)

        ttk.Label(top, text="Secure IPC Framework & Visualizer", font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Button(top, text="Run Pipe", command=self.run_pipe).pack(side="left", padx=4)
        ttk.Button(top, text="Run Queue", command=self.run_msg_queue).pack(side="left", padx=4)
        ttk.Button(top, text="Run Shared", command=self.run_shared_memory).pack(side="left", padx=4)
        ttk.Button(top, text="Run Process Sim", command=self.run_process_sim).pack(side="left", padx=4)
        ttk.Button(top, text="Benchmark", command=self.run_benchmark).pack(side="left", padx=4)

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

        edu = ttk.LabelFrame(parent, text="Educational Mode")
        edu.pack(fill="x", padx=8, pady=6)
        self.lesson_var = tk.StringVar(value="hmac_failure")
        ttk.Combobox(edu, values=sorted(LESSONS.keys()), textvariable=self.lesson_var, state="readonly").pack(fill="x", padx=4, pady=4)
        ttk.Button(edu, text="Show Lesson", command=self.show_lesson).pack(fill="x", padx=4, pady=4)

        sec = ttk.LabelFrame(parent, text="Security Posture")
        sec.pack(fill="both", expand=True, padx=8, pady=6)
        self.posture_text = scrolledtext.ScrolledText(sec, height=10)
        self.posture_text.pack(fill="both", expand=True, padx=4, pady=4)

    def _build_right_panel(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True, padx=8, pady=6)

        timeline_tab = ttk.Frame(nb)
        logs_tab = ttk.Frame(nb)
        nb.add(timeline_tab, text="Protocol Timeline / Packet Inspector")
        nb.add(logs_tab, text="Console")

        cols = ("timestamp", "channel", "action", "sender", "receiver", "size", "hmac_ok", "replayed", "dropped", "note")
        self.timeline = ttk.Treeview(timeline_tab, columns=cols, show="headings", height=15)
        for c in cols:
            self.timeline.heading(c, text=c)
            self.timeline.column(c, width=120 if c != "note" else 220, anchor="w")
        self.timeline.pack(fill="both", expand=True)

        self.console = scrolledtext.ScrolledText(logs_tab, height=20, bg="#111", fg="#ddd", font=("Consolas", 10))
        self.console.pack(fill="both", expand=True)
        self.log("Ready. Configure scenario and run demos.")

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

    def run_in_thread(self, fn, title):
        scenario = self._read_scenario()

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
                if isinstance(result, str):
                    for line in result.splitlines():
                        self.log(line)
            except Exception as e:
                self.log(f"[Error] {e}")
            finally:
                self.log(f"[{title}] Finished.\n")

        threading.Thread(target=worker, daemon=True).start()

    def run_pipe(self):
        self.run_in_thread(lambda k, s: secure_pipe_example(key=k, scenario=s), "Secure Pipe")

    def run_msg_queue(self):
        self.run_in_thread(lambda k, s: secure_message_queue_example(key=k, scenario=s), "Message Queue")

    def run_shared_memory(self):
        self.run_in_thread(lambda k, s: secure_shared_memory_example(key=k, scenario=s), "Shared Memory")

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
        self.log(f"Replay file loaded: {path}")

    def run_benchmark(self):
        scenario = self._read_scenario()

        def worker():
            self.log("[Benchmark] Running comparative benchmarking...")
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

    def show_lesson(self):
        key = self.lesson_var.get()
        txt = LESSONS.get(key, "No lesson available.")
        messagebox.showinfo("Educational Mode", txt)
        self.log(f"Lesson ({key}): {txt}")
