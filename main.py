from gui.visualizer import IPCVisualizer
import tkinter as tk

if __name__ == "__main__":
    root = tk.Tk()
    root.title("🔐 Secure IPC Framework & Visualizer")
    root.geometry("820x520")
    app = IPCVisualizer(root)
    root.mainloop()
