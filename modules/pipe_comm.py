
# Simple secure pipe demo where sender sends (ciphertext, hmac)
#here the code wil start commucnaing in ppoes

from multiprocessing import Process, Pipe, Queue
from .secure_utils import SecureChannel, compute_hmac, verify_hmac

def _sender_pipe(conn, key: bytes, log_q: Queue):
    # note: small, intentionally straightforward sender
    sc = SecureChannel(key)
    plain = "Hello Securely through Pipe"
    enc = sc.encrypt(plain)
    tag = compute_hmac(key, enc)
    # send ciphertext + tag together
    conn.send((enc, tag))
    log_q.put(("sender_plain", plain))
    log_q.put(("sender_enc", repr(enc)))
    log_q.put(("sender_hmac", repr(tag)))
    conn.close()
    log_q.put(("sender_done", None))

def _receiver_pipe(conn, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    try:
        item = conn.recv()
    except EOFError:
        log_q.put(("receiver_error", "no data"))
        conn.close()
        return

    if not item or not isinstance(item, tuple) or len(item) != 2:
        log_q.put(("receiver_invalid_format", repr(item)))
        conn.close()
        return

    enc, tag = item
    log_q.put(("receiver_received_enc", repr(enc)))
    ok = verify_hmac(key, enc, tag)
    log_q.put(("receiver_hmac_ok", str(ok)))
    if not ok:
        log_q.put(("receiver_auth_failed", None))
        conn.close()
        return

    try:
        dec = sc.decrypt(enc)
        log_q.put(("receiver_decrypted", dec))
    except Exception as e:
        log_q.put(("receiver_decrypt_error", str(e)))
    conn.close()
    log_q.put(("receiver_done", None))

def secure_pipe_example(key: bytes = None):
    """
    Run demo and return (log_text, events_list).
    events_list currently empty but kept for animation compatibility.
    """
    parent_conn, child_conn = Pipe()
    log_q = Queue()

    sc = SecureChannel(key)
    key_used = sc.key

    p1 = Process(target=_sender_pipe, args=(parent_conn, key_used, log_q))
    p2 = Process(target=_receiver_pipe, args=(child_conn, key_used, log_q))

    p1.start()
    p2.start()

    p1.join()
    p2.join()

    logs = []
    while not log_q.empty():
        try:
            ev = log_q.get_nowait()
            logs.append(f"{ev[0]}: {ev[1]}")
        except Exception:
            break

    header = "--- Secure Pipe Communication ---"
    footer = "--- Secure Pipe Done ---"
    return "\n".join([header] + logs + [footer]), []
