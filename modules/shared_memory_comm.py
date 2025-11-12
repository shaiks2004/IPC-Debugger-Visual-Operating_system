from multiprocessing import Process, Manager, Queue
from .secure_utils import SecureChannel

def _writer_shared(shared_dict, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    msg = "Shared Secure Data (sensitive)"
    enc = sc.encrypt(msg)
    # store as bytes represented in base64-ish str by simply decoding to latin1 safe text
    # safer approach for cross-process: keep bytes in manager list
    shared_dict['data'] = enc  # manager will proxy the bytes
    log_q.put(f"[Writer] Wrote encrypted to shared memory -> {enc}")
    log_q.put("[Writer] Done")

def _reader_shared(shared_dict, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    enc = shared_dict.get('data', None)
    if enc is None:
        log_q.put("[Reader] No data in shared memory")
    else:
        log_q.put(f"[Reader] Read encrypted from shared memory -> {enc}")
        dec = sc.decrypt(enc)
        log_q.put(f"[Reader] Decrypted -> {dec}")
    log_q.put("[Reader] Done")

def secure_shared_memory_example():
    """
    Uses a Manager dict to simulate shared memory; returns logs string.
    """
    manager = Manager()
    shared_dict = manager.dict()
    log_q = Queue()
    sc = SecureChannel()
    key = sc.key

    p_writer = Process(target=_writer_shared, args=(shared_dict, key, log_q))
    p_reader = Process(target=_reader_shared, args=(shared_dict, key, log_q))

    p_writer.start()
    p_writer.join()

    p_reader.start()
    p_reader.join()

    logs = []
    while not log_q.empty():
        try:
            logs.append(log_q.get_nowait())
        except:
            break

    header = "--- Secure Shared Memory Communication ---"
    footer = "--- Secure Shared Memory Done ---"
    return "\n".join([header] + logs + [footer])
