from modules.msg_queue_comm import secure_message_queue_example
from modules.pipe_comm import secure_pipe_example
from modules.scenario import IPCScenario
from modules.shared_memory_comm import secure_shared_memory_example


def _assert_common(events):
    assert events, "events should not be empty"
    assert all("timestamp" in e for e in events)
    assert all("channel" in e for e in events)


def test_pipe_basic_flow():
    logs, events = secure_pipe_example(scenario=IPCScenario(message_count=2, message_size=8))
    assert "Secure Pipe" in logs
    _assert_common(events)


def test_queue_tamper_detected():
    logs, events = secure_message_queue_example(
        scenario=IPCScenario(message_count=1, message_size=10, tamper_ciphertext=True)
    )
    assert "Secure Message Queue" in logs
    _assert_common(events)
    assert any(e["action"] in {"auth_failed", "decrypt_error"} for e in events)


def test_shared_memory_replay_event():
    logs, events = secure_shared_memory_example(
        scenario=IPCScenario(message_count=1, replay_attack=True)
    )
    assert "Secure Shared Memory" in logs
    _assert_common(events)
    assert any(e.get("replayed") for e in events)
