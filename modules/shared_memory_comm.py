# modules/shared_memory_comm.py
from multiprocessing import Process, Manager, Queue
from .secure_utils import SecureChannel

def _writer_shared(shared_dict, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    msg = "Shared Secure Data"
    enc = sc.encrypt(msg)
    # store bytes in manager by assigning directly (Manager proxies bytes)
    shared_dict['data'] = enc
    log_q.put(("writer_written", enc))
    log_q.put(("writer_done", None))

def _reader_shared(shared_dict, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    enc = shared_dict.get('data', None)
    if enc is None:
        log_q.put(("reader_no_data", None))
    else:
        log_q.put(("reader_read", enc))
        dec = sc.decrypt(enc)
        log_q.put(("reader_dec", dec))
    log_q.put(("reader_done", None))

def secure_shared_memory_example():
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

    events = []
    while not log_q.empty():
        try:
            events.append(log_q.get_nowait())
        except:
            break

    lines = ["--- Secure Shared Memory Communication ---"]
    for ev, payload in events:
        if ev == "writer_written":
            lines.append(f"[Writer] Wrote Encrypted -> {payload}")
        elif ev == "writer_done":
            lines.append("[Writer] Done")
        elif ev == "reader_read":
            lines.append(f"[Reader] Read Encrypted -> {payload}")
        elif ev == "reader_dec":
            lines.append(f"[Reader] Decrypted -> {payload}")
        elif ev == "reader_no_data":
            lines.append("[Reader] No data found")
        elif ev == "reader_done":
            lines.append("[Reader] Done")
    lines.append("--- Secure Shared Memory Done ---")
    return "\n".join(lines), events
