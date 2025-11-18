# gui/visualizer.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from modules.pipe_comm import secure_pipe_example
from modules.msg_queue_comm import secure_message_queue_example
from modules.shared_memory_comm import secure_shared_memory_example
from modules.process_simulation import process_info
import threading
import time


class IPCVisualizer:
    def __init__(self, root):
        self.root = root
        self.setup_ui()

    def setup_ui(self):
        # Title
        title = ttk.Label(
            self.root,
            text="🔐 Secure IPC Framework & Visualizer",
            font=("Segoe UI", 18, "bold")
        )
        title.pack(pady=8)

        # Buttons Frame
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=6)

        ttk.Button(
            button_frame, text="Secure Pipe", width=28,
            command=self.run_pipe
        ).grid(row=0, column=0, padx=8, pady=8)

        ttk.Button(
            button_frame, text="Secure Message Queue", width=28,
            command=self.run_msg_queue
        ).grid(row=0, column=1, padx=8, pady=8)

        ttk.Button(
            button_frame, text="Secure Shared Memory", width=28,
            command=self.run_shared_memory
        ).grid(row=1, column=0, padx=8, pady=8)

        ttk.Button(
            button_frame, text="Process Simulation", width=28,
            command=self.run_process_sim
        ).grid(row=1, column=1, padx=8, pady=8)

        # Canvas
        self.canvas = tk.Canvas(
            self.root, width=860, height=200,
            bg="#ffffff",
            highlightthickness=1, highlightbackground="#ccc"
        )
        self.canvas.pack(padx=12, pady=10)

        self._draw_static_scene()

        # Console Area
        console_frame = ttk.Frame(self.root)
        console_frame.pack(fill="both", expand=True, padx=12, pady=6)

        self.console = scrolledtext.ScrolledText(
            console_frame,
            height=18,         # Fixed updated height
            width=115,
            bg="#1e1e1e",
            fg="#d4d4d4",
            font=("Consolas", 10),
            insertbackground="#ffffff",
            wrap=tk.WORD
        )
        self.console.pack(fill="both", expand=True)
        self.log("Ready. Click a button to run secure IPC demo.\n")

    # Static Layout
    def _draw_static_scene(self):
        self.canvas.delete("all")

        # Sender
        self.canvas.create_oval(
            80, 60, 180, 160,
            fill="#d0eaff", outline="#1a73e8", width=2, tags="sender"
        )
        self.canvas.create_text(130, 110, text="Sender",
                                font=("Segoe UI", 12, "bold"))

        # Receiver
        self.canvas.create_oval(
            680, 60, 780, 160,
            fill="#ffe8d6", outline="#ff7a00", width=2, tags="receiver"
        )
        self.canvas.create_text(730, 110, text="Receiver",
                                font=("Segoe UI", 12, "bold"))

        # Baseline dotted line
        self.canvas.create_line(
            190, 110, 680, 110,
            dash=(4, 6), fill="#888", width=1
        )

    # Console Logging
    def log(self, message: str):
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)

    def clear_console(self):
        self.console.delete(1.0, tk.END)

    # Run in background thread
    def run_in_thread(self, func, title):
        def worker():
            self.log(f"[{title}] Starting...\n")
            try:
                result, events = func()

                # Log output lines
                if isinstance(result, str):
                    for line in result.splitlines():
                        self.log(line)

                # Animate events
                if isinstance(events, list) and len(events) > 0:
                    self._animate_events(events)

            except Exception as e:
                self.log(f"[Error] {e}")

            self.log(f"[{title}] Finished.\n")

        threading.Thread(target=worker, daemon=True).start()

    # Event animations
    def _animate_events(self, events):
        for ev, payload in events:
            if ev in ("send_enc", "send_plain", "queued", "writer_written"):
                self._animate_token("ENC")
                time.sleep(0.5)
            elif ev in ("recv_enc", "recv_dec", "reader_read", "reader_dec"):
                time.sleep(0.2)
            else:
                time.sleep(0.1)

    # Token animation
    def _animate_token(self, label_text):
        x0 = 190
        y0 = 96
        size = 20

        token = self.canvas.create_rectangle(
            x0, y0 - size // 2, x0 + size, y0 + size // 2,
            fill="#7bd389", outline="#2d8f4a"
        )
        text = self.canvas.create_text(
            x0 + size / 2, y0, text=label_text,
            font=("Segoe UI", 8, "bold"), fill="#003300"
        )

        steps = 40
        dx = (680 - x0) / steps

        for _ in range(steps):
            self.canvas.move(token, dx, 0)
            self.canvas.move(text, dx, 0)
            self.canvas.update()
            time.sleep(0.01)

        # Flash receiver area
        original_fill = self.canvas.itemcget("receiver", "fill")
        self.canvas.itemconfig("receiver", fill="#c7ffd6")
        self.canvas.update()
        time.sleep(0.12)
        self.canvas.itemconfig("receiver", fill=original_fill)

        # Delete token
        self.canvas.delete(token)
        self.canvas.delete(text)

    # Button actions
    def run_pipe(self):
        messagebox.showinfo(
            "Secure Pipe",
            "Running Secure Pipe Communication.\nCheck logs and animation below."
        )
        self.run_in_thread(secure_pipe_example, "Secure Pipe")

    def run_msg_queue(self):
        messagebox.showinfo(
            "Secure Message Queue",
            "Running Message Queue Communication.\nCheck logs and animation below."
        )
        self.run_in_thread(secure_message_queue_example, "Secure Message Queue")

    def run_shared_memory(self):
        messagebox.showinfo(
            "Secure Shared Memory",
            "Running Shared Memory Communication.\nCheck logs below."
        )
        self.run_in_thread(secure_shared_memory_example, "Shared Memory")

    def run_process_sim(self):
        messagebox.showinfo(
            "Process Simulation",
            "Running process simulation.\nCheck logs below."
        )

        def fn():
            txt = process_info("Demo Process")
            return txt, []

        self.run_in_thread(fn, "Process Simulation")