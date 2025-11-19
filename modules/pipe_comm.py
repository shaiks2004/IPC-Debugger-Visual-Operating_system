from multiprocessing import Process, Pipe, Queue
from .secure_utils import SecureChannel
from cryptography.fernet import Fernet

def _sender_pipe(conn, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    data = "Hello Securely through Pipe"
    enc = sc.encrypt(data)
    log_q.put(f"[Sender] Plain -> {data}")
    log_q.put(f"[Sender] Encrypted (bytes) -> {enc}")
    conn.send(enc)
    conn.close()
    log_q.put("[Sender] Sent encrypted data via pipe")

def _receiver_pipe(conn, key: bytes, log_q: Queue):
    sc = SecureChannel(key)
    enc = conn.recv()
    log_q.put(f"[Receiver] Received encrypted (bytes) -> {enc}")
    dec = sc.decrypt(enc)
    log_q.put(f"[Receiver] Decrypted -> {dec}")
    conn.close()
    log_q.put("[Receiver] Done")

def secure_pipe_example():
    """
    Runs a secure pipe demo and returns the aggregated logs as a string.
    """
    parent_conn, child_conn = Pipe()
    log_q = Queue()

    sc = SecureChannel()  # generate key once
    key = sc.key

    p_sender = Process(target=_sender_pipe, args=(parent_conn, key, log_q))
    p_receiver = Process(target=_receiver_pipe, args=(child_conn, key, log_q))

    p_sender.start()
    p_receiver.start()

    p_sender.join()
    p_receiver.join()

    # Collect logs
    logs = []
    while not log_q.empty():
        try:
            logs.append(log_q.get_nowait())
        except:
            break

    header = "--- Secure Pipe Communication ---"
    footer = "--- Secure Pipe Done ---"
    return "\n".join([header] + logs + [footer])
