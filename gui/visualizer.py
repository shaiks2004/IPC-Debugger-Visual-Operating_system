import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from modules.pipe_comm import secure_pipe_example
from modules.msg_queue_comm import secure_message_queue_example
from modules.shared_memory_comm import secure_shared_memory_example
from modules.process_simulation import process_info
import threading

class IPCVisualizer:
    def __init__(self, root):
        self.root = root
        self.setup_ui()

    def setup_ui(self):
        title = ttk.Label(self.root, text="🔐 Secure IPC Framework & Visualizer", font=("Segoe UI", 18, "bold"))
        title.pack(pady=12)

        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=6)

        ttk.Button(button_frame, text="🔗 Secure Pipe", width=25, command=self.run_pipe).grid(row=0, column=0, padx=8, pady=8)
        ttk.Button(button_frame, text="📦 Secure Message Queue", width=25, command=self.run_msg_queue).grid(row=0, column=1, padx=8, pady=8)
        ttk.Button(button_frame, text="🧠 Secure Shared Memory", width=25, command=self.run_shared_memory).grid(row=1, column=0, padx=8, pady=8)
        ttk.Button(button_frame, text="⚙️ Process Simulation", width=25, command=self.run_process_sim).grid(row=1, column=1, padx=8, pady=8)

        # Console area (scrolled text)
        self.console = scrolledtext.ScrolledText(self.root, height=16, width=95, bg="#0f0f0f", fg="#d2ffd2")
        self.console.pack(padx=12, pady=12)
        self.console.insert(tk.END, "Ready. Click any button to run a secure IPC demo.\n")

    def log(self, message: str):
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)

    def clear_console(self):
        self.console.delete(1.0, tk.END)

    # run functions in a separate thread to avoid blocking Tk mainloop
    def run_in_thread(self, target_func, title_msg):
        def worker():
            self.log(f"[{title_msg}] Starting...")
            try:
                result = target_func()
                # If the function returned logs, display them; else show default
                if isinstance(result, str):
                    for line in result.splitlines():
                        self.log(line)
                else:
                    self.log("[Info] No textual logs returned by the module.")
            except Exception as e:
                self.log(f"[Error] Exception: {e}")
            self.log(f"[{title_msg}] Finished.\n")

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def run_pipe(self):
        messagebox.showinfo("Secure Pipe", "Running Secure Pipe Communication (check console)")
        self.run_in_thread(secure_pipe_example, "Secure Pipe")

    def run_msg_queue(self):
        messagebox.showinfo("Secure Message Queue", "Running Secure Message Queue (check console)")
        self.run_in_thread(secure_message_queue_example, "Secure Message Queue")

    def run_shared_memory(self):
        messagebox.showinfo("Secure Shared Memory", "Running Secure Shared Memory (check console)")
        self.run_in_thread(secure_shared_memory_example, "Secure Shared Memory")

    def run_process_sim(self):
        messagebox.showinfo("Process Simulation", "Simulating process info (check console)")
        # run process_info inside thread so GUI doesn't freeze; process_info returns a string
        self.run_in_thread(lambda: process_info("Demo Process"), "Process Simulation")
