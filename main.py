#all modulesakjsdnias
import tkinter as tk
from gui.visualizer import IPCVisualizer

def main():
    root = tk.Tk()
    root.title("Secure IPC Visualization Tool")
    # window size - tweak if needed
    root.geometry("980x760")
    app = IPCVisualizer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
