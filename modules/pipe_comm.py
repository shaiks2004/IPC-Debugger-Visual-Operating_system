# modules/pipe_comm.py
from multiprocessing import Process, Pipe, Queue
from .secure_utils import SecureChannel

def _sender_pipe(conn, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    data = "Hello via Secure Pipe"
    enc = sc.encrypt(data)
    log_q.put(("send_plain", data))
    log_q.put(("send_enc", enc))
    conn.send(enc)
    conn.close()
    log_q.put(("sent", None))

def _receiver_pipe(conn, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    enc = conn.recv()
    log_q.put(("recv_enc", enc))
    dec = sc.decrypt(enc)
    log_q.put(("recv_dec", dec))
    conn.close()
    log_q.put(("recv_done", None))

def secure_pipe_example():
    """
    Runs secure pipe demo and returns logs (string) AND list of events for animation.
    We'll collect events via a Queue and then return them as text.
    """
    parent_conn, child_conn = Pipe()
    log_q = Queue()

    sc = SecureChannel()
    key = sc.key

    p1 = Process(target=_sender_pipe, args=(parent_conn, key, log_q))
    p2 = Process(target=_receiver_pipe, args=(child_conn, key, log_q))

    p1.start()
    p2.start()

    p1.join()
    p2.join()

    # Collect all events
    events = []
    while not log_q.empty():
        try:
            events.append(log_q.get_nowait())
        except:
            break

    # Build readable logs
    lines = ["--- Secure Pipe Communication ---"]
    for ev, payload in events:
        if ev == "send_plain":
            lines.append(f"[Sender] Plain -> {payload}")
        elif ev == "send_enc":
            lines.append(f"[Sender] Encrypted -> {payload}")
        elif ev == "sent":
            lines.append("[Sender] Sent via pipe")
        elif ev == "recv_enc":
            lines.append(f"[Receiver] Received Encrypted -> {payload}")
        elif ev == "recv_dec":
            lines.append(f"[Receiver] Decrypted -> {payload}")
        elif ev == "recv_done":
            lines.append("[Receiver] Done")
    lines.append("--- Secure Pipe Done ---")
    # return logs and events (events useful for animation)
    return "\n".join(lines), events

