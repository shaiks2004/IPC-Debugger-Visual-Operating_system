import os
import time

def process_info(name="Demo Process"):
    logs = []
    logs.append(f"[Process: {name}] PID: {os.getpid()}")
    # Simulate some state changes
    logs.append(f"[Process: {name}] State -> NEW")
    time.sleep(0.3)
    logs.append(f"[Process: {name}] State -> READY")
    time.sleep(0.3)
    logs.append(f"[Process: {name}] State -> RUNNING")
    time.sleep(0.3)
    logs.append(f"[Process: {name}] State -> TERMINATED")
    return "\n".join(logs)
