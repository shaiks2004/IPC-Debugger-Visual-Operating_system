from multiprocessing import Process, Queue
from .secure_utils import SecureChannel

def _sender_queue(queue: Queue, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    messages = ["Secure Data 1", "Secure Data 2", "Secure Data 3"]
    for m in messages:
        enc = sc.encrypt(m)
        log_q.put(f"[Sender] Plain -> {m}")
        log_q.put(f"[Sender] Encrypted -> {enc}")
        queue.put(enc)
    # signal receiver to stop
    queue.put(None)
    log_q.put("[Sender] All messages queued")

def _receiver_queue(queue: Queue, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    while True:
        item = queue.get()
        if item is None:
            break
        log_q.put(f"[Receiver] Received encrypted -> {item}")
        dec = sc.decrypt(item)
        log_q.put(f"[Receiver] Decrypted -> {dec}")
    log_q.put("[Receiver] Done")

def secure_message_queue_example():
    """
    Runs a secure message-queue demo and returns logs as string.
    """
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

    logs = []
    while not log_q.empty():
        try:
            logs.append(log_q.get_nowait())
        except:
            break

    header = "--- Secure Message Queue Communication ---"
    footer = "--- Secure Message Queue Done ---"
    return "\n".join([header] + logs + [footer])
