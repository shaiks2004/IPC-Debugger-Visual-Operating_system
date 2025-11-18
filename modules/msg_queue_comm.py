# modules/msg_queue_comm.py
from multiprocessing import Process, Queue
from .secure_utils import SecureChannel

def _sender_queue(queue: Queue, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    messages = ["Secure Msg A", "Secure Msg B"]
    for m in messages:
        enc = sc.encrypt(m)
        log_q.put(("send_plain", m))
        log_q.put(("send_enc", enc))
        queue.put(enc)
        log_q.put(("queued", None))
    queue.put(None)
    log_q.put(("sender_done", None))

def _receiver_queue(queue: Queue, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    while True:
        item = queue.get()
        if item is None:
            break
        log_q.put(("recv_enc", item))
        dec = sc.decrypt(item)
        log_q.put(("recv_dec", dec))
    log_q.put(("receiver_done", None))

def secure_message_queue_example():
    queue = Queue()
    log_q = Queue()
    sc = SecureChannel()
    key = sc.key

    p_sender = Process(target=_sender_queue, args=(queue, key, log_q))
    p_receiver = Process(target=_receiver_queue, args=(queue, key, log_q))

    p_sender.start()
    p_receiver.start()
    p_sender.join()
    p_receiver.join()

    events = []
    while not log_q.empty():
        try:
            events.append(log_q.get_nowait())
        except:
            break

    lines = ["--- Secure Message Queue Communication ---"]
    for ev, payload in events:
        if ev == "send_plain":
            lines.append(f"[Sender] Plain -> {payload}")
        elif ev == "send_enc":
            lines.append(f"[Sender] Encrypted -> {payload}")
        elif ev == "queued":
            lines.append("[Sender] Queued message")
        elif ev == "recv_enc":
            lines.append(f"[Receiver] Received Encrypted -> {payload}")
        elif ev == "recv_dec":
            lines.append(f"[Receiver] Decrypted -> {payload}")
        elif ev == "sender_done":
            lines.append("[Sender] Done")
        elif ev == "receiver_done":
            lines.append("[Receiver] Done")
    lines.append("--- Secure Message Queue Done ---")
    return "\n".join(lines), events