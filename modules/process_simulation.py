# modules/process_simulation.py
import os
import time

def process_info(name="Demo Process"):
    logs = []
    logs.append(f"[Process] Name: {name} | PID: {os.getpid()}")
    logs.append("[Process] State -> NEW")
    time.sleep(0.1)
    logs.append("[Process] State -> READY")
    time.sleep(0.1)
    logs.append("[Process] State -> RUNNING")
    time.sleep(0.1)
    logs.append("[Process] State -> TERMINATED")
    return "\n".join(logs)



