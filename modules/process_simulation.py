import os
import time

def process_info(name="Demo Process"):
    logs = []
    logs.append(f"Process: {name} | PID: {os.getpid()}")
    logs.append("State: NEW")
    time.sleep(0.08)
    logs.append("State: READY")
    time.sleep(0.08)
    logs.append("State: RUNNING")
    time.sleep(0.08)
    logs.append("State: TERMINATED")
    return "\n".join(logs)
