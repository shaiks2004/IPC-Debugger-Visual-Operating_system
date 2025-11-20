# Secure message queue demo: put (ciphertext, hmac) tuples in a Queue
#messages of the uaseqw
from multiprocessing import Process, Queue
from .secure_utils import SecureChannel, compute_hmac, verify_hmac

def _sender_queue(q: Queue, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    messages = ["Secure Data 1", "Secure Data 2"]
    for m in messages:
        enc = sc.encrypt(m)
        tag = compute_hmac(key, enc)
        q.put((enc, tag))
        log_q.put(("send_plain", m))
        log_q.put(("send_enc", repr(enc)))
        log_q.put(("queued", None))
    # signal end
    q.put(None)
    log_q.put(("sender_done", None))

def _receiver_queue(q: Queue, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    while True:
        item = q.get()
        if item is None:
            break
        if not isinstance(item, tuple) or len(item) != 2:
            log_q.put(("recv_invalid", repr(item)))
            continue
        enc, tag = item
        ok = verify_hmac(key, enc, tag)
        log_q.put(("recv_hmac_ok", str(ok)))
        if not ok:
            log_q.put(("recv_auth_failed", None))
            continue
        try:
            dec = sc.decrypt(enc)
            log_q.put(("recv_decrypted", dec))
        except Exception as e:
            log_q.put(("recv_decrypt_error", str(e)))
    log_q.put(("receiver_done", None))

def secure_message_queue_example(key: bytes = None):
    queue = Queue()
    log_q = Queue()
    sc = SecureChannel(key)
    key_used = sc.key

    ps = Process(target=_sender_queue, args=(queue, key_used, log_q))
    pr = Process(target=_receiver_queue, args=(queue, key_used, log_q))

    ps.start()
    pr.start()

    ps.join()
    pr.join()

    logs = []
    events = []
    while not log_q.empty():
        try:
            ev = log_q.get_nowait()
            logs.append(f"{ev[0]}: {ev[1]}")
            events.append(ev)
        except Exception:
            break

    header = "--- Secure Message Queue Communication ---"
    footer = "--- Secure Message Queue Done ---"
    return "\n".join([header] + logs + [footer]), events
