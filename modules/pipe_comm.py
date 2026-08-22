from __future__ import annotations

import os
import time
from multiprocessing import Process, Pipe, Queue

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


def _sender_pipe(conn, key: bytes, log_q: Queue, scenario: IPCScenario):
    sc = SecureChannel(key)
    pid = os.getpid()
    payload = ("P" * max(1, scenario.message_size))[: scenario.message_size]
    for idx in range(max(1, scenario.message_count)):
        plain = f"msg-{idx}:{payload}"
        enc = sc.encrypt(plain)
        tag = compute_hmac(key, enc)

        if scenario.drop_packet and idx == 0:
            log_q.put(_event("pipe", "drop_packet", sender_pid=pid, payload=enc, dropped=True, note="Dropped by attack toggle"))
            continue

        if scenario.tamper_ciphertext and idx == 0:
            enc = enc[:-1] + bytes([enc[-1] ^ 0x01])
            log_q.put(_event("pipe", "tamper_ciphertext", sender_pid=pid, payload=enc, note="Ciphertext byte flipped"))

        conn.send((enc, tag))
        log_q.put(_event("pipe", "send", sender_pid=pid, payload=enc, note="Ciphertext+HMAC sent"))

        if scenario.replay_attack and idx == 0:
            conn.send((enc, tag))
            log_q.put(_event("pipe", "replay", sender_pid=pid, payload=enc, replayed=True, note="Replayed previous packet"))

        time.sleep(max(scenario.interval_ms, 0) / 1000)

    conn.send(None)
    conn.close()


def _receiver_pipe(conn, key: bytes, log_q: Queue, scenario: IPCScenario):
    receiver_key = SecureChannel().key if scenario.key_mismatch else key
    sc = SecureChannel(receiver_key)
    pid = os.getpid()
    seen = set()

    while True:
        try:
            item = conn.recv()
        except EOFError:
            log_q.put(_event("pipe", "recv_eof", receiver_pid=pid, note="EOF reached"))
            break

        if item is None:
            break

        if not isinstance(item, tuple) or len(item) != 2:
            log_q.put(_event("pipe", "recv_invalid_format", receiver_pid=pid, note=repr(item)))
            continue

        enc, tag = item
        fingerprint = enc[:24]
        replayed = fingerprint in seen
        seen.add(fingerprint)

        ok = verify_hmac(key, enc, tag)
        log_q.put(_event("pipe", "recv", receiver_pid=pid, payload=enc, hmac_ok=ok, replayed=replayed))

        if not ok:
            log_q.put(_event("pipe", "auth_failed", receiver_pid=pid, payload=enc, hmac_ok=False, note="HMAC verification failed"))
            continue

        try:
            _ = sc.decrypt(enc)
            log_q.put(_event("pipe", "decrypt_ok", receiver_pid=pid, payload=enc, note="Decryption successful"))
        except Exception as e:
            log_q.put(_event("pipe", "decrypt_error", receiver_pid=pid, payload=enc, note=str(e)))

    conn.close()


def secure_pipe_example(key: bytes = None, scenario: IPCScenario | None = None):
    scenario = scenario or IPCScenario()
    parent_conn, child_conn = Pipe()
    log_q = Queue()

    sc = SecureChannel(key)
    key_used = sc.key

    p_sender = Process(target=_sender_pipe, args=(parent_conn, key_used, log_q, scenario))
    p_receiver = Process(target=_receiver_pipe, args=(child_conn, key_used, log_q, scenario))

    if scenario.race_condition:
        p_receiver.start()
        time.sleep(0.03)
        p_sender.start()
    else:
        p_sender.start()
        p_receiver.start()

    p_sender.join()
    p_receiver.join()

    events = []
    while not log_q.empty():
        try:
            events.append(log_q.get_nowait())
        except Exception:
            break

    logs = ["--- Secure Pipe Communication ---"]
    for ev in events:
        logs.append(f"{ev['action']}: {ev.get('note', '')} hmac_ok={ev.get('hmac_ok')}")
    logs.append("--- Secure Pipe Done ---")
    return "\n".join(logs), events
