from __future__ import annotations

import os
import time
from multiprocessing import Process, Manager, Queue

from .event_model import ProtocolEvent, now_ts
from .scenario import IPCScenario
from .secure_utils import SecureChannel, compute_hmac, verify_hmac


def _event(channel: str, action: str, sender_pid=None, receiver_pid=None, payload=b"", hmac_ok=None, replayed=False, dropped=False, note=""):
    return ProtocolEvent(
        timestamp=now_ts(),
        channel=channel,
        action=action,
        sender_pid=sender_pid,
        receiver_pid=receiver_pid,
        payload_size=len(payload) if payload else 0,
        hmac_ok=hmac_ok,
        replayed=replayed,
        dropped=dropped,
        note=note,
    ).to_dict()


def _writer_shared(shared, key: bytes, log_q: Queue, scenario: IPCScenario):
    sc = SecureChannel(key)
    pid = os.getpid()
    payload = ("S" * max(1, scenario.message_size))[: scenario.message_size]

    for idx in range(max(1, scenario.message_count)):
        msg = f"shared-msg-{idx}:{payload}"
        enc = sc.encrypt(msg)
        tag = compute_hmac(key, enc)

        if scenario.drop_packet and idx == 0:
            log_q.put(_event("shared_memory", "drop_packet", sender_pid=pid, payload=enc, dropped=True))
            continue

        if scenario.tamper_ciphertext and idx == 0:
            enc = enc[:-1] + bytes([enc[-1] ^ 0x01])
            log_q.put(_event("shared_memory", "tamper_ciphertext", sender_pid=pid, payload=enc))

        shared["packet"] = (enc, tag)
        log_q.put(_event("shared_memory", "write", sender_pid=pid, payload=enc, note="Packet written to shared dict"))

        if scenario.replay_attack and idx == 0:
            shared["packet_replay"] = (enc, tag)
            log_q.put(_event("shared_memory", "replay", sender_pid=pid, payload=enc, replayed=True))

        time.sleep(max(scenario.interval_ms, 0) / 1000)

    shared["done"] = True


def _reader_shared(shared, key: bytes, log_q: Queue, scenario: IPCScenario):
    receiver_key = SecureChannel().key if scenario.key_mismatch else key
    sc = SecureChannel(receiver_key)
    pid = os.getpid()

    while not shared.get("done", False) and "packet" not in shared:
        time.sleep(0.01)

    packet_keys = ["packet", "packet_replay"]
    for k in packet_keys:
        packet = shared.get(k)
        if packet is None:
            continue
        enc, tag = packet
        ok = verify_hmac(key, enc, tag)
        log_q.put(_event("shared_memory", "read", receiver_pid=pid, payload=enc, hmac_ok=ok, replayed=(k == "packet_replay")))

        if not ok:
            log_q.put(_event("shared_memory", "auth_failed", receiver_pid=pid, payload=enc, hmac_ok=False))
            continue

        try:
            _ = sc.decrypt(enc)
            log_q.put(_event("shared_memory", "decrypt_ok", receiver_pid=pid, payload=enc))
        except Exception as e:
            log_q.put(_event("shared_memory", "decrypt_error", receiver_pid=pid, payload=enc, note=str(e)))


def secure_shared_memory_example(key: bytes = None, scenario: IPCScenario | None = None):
    scenario = scenario or IPCScenario()
    m = Manager()
    shared = m.dict()
    log_q = Queue()

    sc = SecureChannel(key)
    key_used = sc.key

    pw = Process(target=_writer_shared, args=(shared, key_used, log_q, scenario))
    pr = Process(target=_reader_shared, args=(shared, key_used, log_q, scenario))

    if scenario.race_condition:
        pr.start()
        time.sleep(0.02)
        pw.start()
    else:
        pw.start()
        pr.start()

    pw.join()
    pr.join()

    events = []
    while not log_q.empty():
        try:
            events.append(log_q.get_nowait())
        except Exception:
            break

    logs = ["--- Secure Shared Memory Communication ---"]
    for ev in events:
        logs.append(f"{ev['action']}: {ev.get('note', '')} hmac_ok={ev.get('hmac_ok')}")
    logs.append("--- Secure Shared Memory Done ---")
    return "\n".join(logs), events
