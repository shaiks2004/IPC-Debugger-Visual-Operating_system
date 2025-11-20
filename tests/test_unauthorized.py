# Simple demonstration test: writer writes encrypted data; rogue reader uses different key.

from multiprocessing import Manager, Process, Queue
from modules.shared_memory_comm import _writer_shared  # using internal helper for demo
from modules.secure_utils import SecureChannel
import time

def rogue_reader(shared):
    # rogue uses a DIFFERENT random key (not the writer's key)
    sc = SecureChannel()  # generates new key
    enc = shared.get('data', None)
    if enc is None:
        print("Rogue: no data")
        return
    print("Rogue read encrypted blob:", repr(enc))
    try:
        # will fail because different key
        print("Rogue attempting decrypt:", sc.decrypt(enc))
    except Exception as e:
        print("Rogue decrypt failed:", e)

if __name__ == "__main__":
    mgr = Manager()
    shared = mgr.dict()
    logq = Queue()

    # writer uses its own SecureChannel
    sc = SecureChannel()
    key = sc.key

    # run writer (authorized)
    w = Process(target=_writer_shared, args=(shared, key, logq))
    w.start()
    w.join()

    # allow small pause
    time.sleep(0.2)

    # rogue tries to read and decrypt
    r = Process(target=rogue_reader, args=(shared,))
    r.start()
    r.join()

    print("Test completed.")
