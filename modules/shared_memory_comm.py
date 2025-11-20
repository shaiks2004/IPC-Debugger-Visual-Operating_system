# Use Manager dict to simulate shared memory. Store encrypted bytes only.
#lrneind
from multiprocessing import Process, Manager, Queue
from .secure_utils import SecureChannel

def _writer_shared(shared, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    msg = "Shared Secure Data (sensitive)"
    enc = sc.encrypt(msg)
    # store ciphertext only
    shared['data'] = enc
    log_q.put(("writer_written", repr(enc)))
    log_q.put(("writer_done", None))

def _reader_shared(shared, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    enc = shared.get('data', None)
    if enc is None:
        log_q.put(("reader_no_data", None))
        log_q.put(("reader_done", None))
        return
    log_q.put(("reader_read_enc", repr(enc)))
    try:
        dec = sc.decrypt(enc)
        log_q.put(("reader_decrypted", dec))
    except Exception as e:
        log_q.put(("reader_decrypt_error", str(e)))
    log_q.put(("reader_done", None))

def secure_shared_memory_example(key: bytes = None):
    m = Manager()
    shared = m.dict()
    log_q = Queue()
    sc = SecureChannel(key)
    key_used = sc.key

    pw = Process(target=_writer_shared, args=(shared, key_used, log_q))
    pr = Process(target=_reader_shared, args=(shared, key_used, log_q))

    pw.start()
    pw.join()
    pr.start()
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

    header = "--- Secure Shared Memory Communication ---"
    footer = "--- Secure Shared Memory Done ---"
    return "\n".join([header] + logs + [footer]), events
