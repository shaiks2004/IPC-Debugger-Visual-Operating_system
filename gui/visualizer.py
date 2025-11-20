#communication tot the UI star the er

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
from modules.pipe_comm import secure_pipe_example
from modules.msg_queue_comm import secure_message_queue_example
from modules.shared_memory_comm import secure_shared_memory_example
from modules.process_simulation import process_info
from modules.secure_utils import derive_key_from_password
import threading

class IPCVisualizer:
    def __init__(self, root):
        self.root = root
        self.user_key = None
        self.anim_in_progress = False
        self.anim_queue = []
        self.setup_ui()
        # ask passphrase at start
        self._ask_passphrase()

    def _ask_passphrase(self):
        pwd = simpledialog.askstring("Passphrase", "Enter passphrase to derive key (leave blank to generate):", show='*', parent=self.root)
        if not pwd:
            # use generated key - fine for demo but mention in report
            self.user_key = None
            messagebox.showinfo("Info", "No passphrase entered: using generated keys.")
            return
        key, salt = derive_key_from_password(pwd)
        self.user_key = key
        self.log("Passphrase accepted. Key derived (not stored).")

    def setup_ui(self):
        title = ttk.Label(self.root, text="Secure IPC Framework & Visualizer", font=("Segoe UI", 16, "bold"))
        title.pack(pady=8)

        bf = ttk.Frame(self.root)
        bf.pack(pady=6)

        ttk.Button(bf, text="Secure Pipe", width=22, command=self.run_pipe).grid(row=0, column=0, padx=6, pady=6)
        ttk.Button(bf, text="Secure Message Queue", width=22, command=self.run_msg_queue).grid(row=0, column=1, padx=6, pady=6)
        ttk.Button(bf, text="Secure Shared Memory", width=22, command=self.run_shared_memory).grid(row=1, column=0, padx=6, pady=6)
        ttk.Button(bf, text="Process Simulation", width=22, command=self.run_process_sim).grid(row=1, column=1, padx=6, pady=6)

        self.canvas = tk.Canvas(self.root, width=920, height=260, bg="#f7f7f7")
        self.canvas.pack(padx=10, pady=8)
        self._draw_scene()

        cf = ttk.Frame(self.root)
        cf.pack(fill="both", expand=True, padx=10, pady=6)

        self.console = scrolledtext.ScrolledText(cf, height=16, bg="#111", fg="#ddd", font=("Consolas", 10))
        self.console.pack(fill="both", expand=True)
        self.log("Ready. Use buttons to run demos.")

    def _draw_scene(self):
        self.canvas.delete("all")
        # sender
        self.canvas.create_oval(80, 40, 160, 120, fill="#e0f7fa", outline="#00796b", width=2, tags="sender")
        self.canvas.create_text(120, 80, text="Sender\nProcess", font=("Segoe UI", 9, "bold"))
        # receiver
        self.canvas.create_oval(760, 40, 840, 120, fill="#fff3e0", outline="#e65100", width=2, tags="receiver")
        self.canvas.create_text(800, 80, text="Receiver\nProcess", font=("Segoe UI", 9, "bold"))
        # baseline
        self.canvas.create_line(170, 80, 760, 80, dash=(4,4), fill="#888")
        # lower area placeholder for queue/memory visualization
        self.canvas.create_rectangle(150, 180, 770, 240, outline="#9e9e9e", width=1)
        self.canvas.create_text(460, 160, text="Kernel / Queue / Shared Memory area", font=("Segoe UI", 9))

    def log(self, text):
        self.console.insert(tk.END, text + "\n")
        self.console.see(tk.END)

    def run_in_thread(self, fn, title):
        def worker():
            self.log(f"[{title}] Starting...")
            try:
                if self.user_key:
                    result, events = fn(self.user_key)
                else:
                    result, events = fn()
                if isinstance(result, str) and result:
                    for line in result.splitlines():
                        self.log(line)
                # queue small animation events if provided
                if isinstance(events, list) and events:
                    self.anim_queue.extend(events)
                    self.root.after(60, self._process_anim_queue)
            except Exception as e:
                self.log(f"[Error] {e}")
            finally:
                self.log(f"[{title}] Finished.\n")
        threading.Thread(target=worker, daemon=True).start()

    def _process_anim_queue(self):
        if self.anim_in_progress or not self.anim_queue:
            return
        ev = self.anim_queue.pop(0)
        # naive mapping
        tag = ev[0] if isinstance(ev, tuple) else str(ev)
        if tag in ("send_enc", "send_plain"):
            self.anim_in_progress = True
            self._anim_top_token(on_done=self._anim_done)
        elif tag in ("queued", "writer_written"):
            self.anim_in_progress = True
            self._anim_drop_to_kernel(on_done=self._anim_done)
        else:
            self.root.after(80, self._anim_done)

    def _anim_done(self):
        self.anim_in_progress = False
        if self.anim_queue:
            self.root.after(40, self._process_anim_queue)

    def _anim_top_token(self, on_done=None):
        x, y = 170, 80
        r = 16
        token = self.canvas.create_oval(x-r, y-r, x+r, y+r, fill="#a5d6a7", outline="#388e3c")
        label = self.canvas.create_text(x, y, text="ENC", font=("Segoe UI", 8))
        target = 760
        step = 8
        delay = 30
        def step_move():
            nonlocal x
            if x >= target:
                # flash receiver
                old = self.canvas.itemcget("receiver", "fill")
                self.canvas.itemconfig("receiver", fill="#c8e6c9")
                self.root.after(150, lambda: self.canvas.itemconfig("receiver", fill=old))
                self.canvas.delete(token)
                self.canvas.delete(label)
                if on_done:
                    on_done()
                return
            x += step
            self.canvas.move(token, step, 0)
            self.canvas.move(label, step, 0)
            self.root.after(delay, step_move)
        step_move()

    def _anim_drop_to_kernel(self, on_done=None):
        # drop a small message rectangle from sender down into the kernel box
        sx, sy = 120, 140
        tx, ty = 460, 210
        w, h = 40, 20
        rect = self.canvas.create_rectangle(sx-w//2, sy-h//2, sx+w//2, sy+h//2, fill="#fff59d", outline="#f57f17")
        txt = self.canvas.create_text(sx, sy, text="m", font=("Segoe UI", 8, "bold"))
        steps = 24
        dx = (tx - sx)/steps
        dy = (ty - sy)/steps
        i = 0
        def step_move():
            nonlocal i
            if i >= steps:
                # put the item visually inside kernel area - we simply keep it there
                if on_done:
                    on_done()
                return
            self.canvas.move(rect, dx, dy)
            self.canvas.move(txt, dx, dy)
            i += 1
            self.root.after(30, step_move)
        step_move()

    # handlers
    def run_pipe(self):
        messagebox.showinfo("Secure Pipe", "Running secure pipe demo.")
        self.run_in_thread(secure_pipe_example, "Secure Pipe")

    def run_msg_queue(self):
        messagebox.showinfo("Secure Message Queue", "Running secure message queue demo.")
        self.run_in_thread(secure_message_queue_example, "Message Queue")

    def run_shared_memory(self):
        messagebox.showinfo("Secure Shared Memory", "Running shared memory demo.")
        self.run_in_thread(secure_shared_memory_example, "Shared Memory")

    def run_process_sim(self):
        messagebox.showinfo("Process Simulation", "Simulating process info.")
        def fn():
            txt = process_info("Demo Process")
            return txt, []
        self.run_in_thread(fn, "Process Simulation")
