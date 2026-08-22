from modules.plugins import get_plugin, list_plugins
from modules.replay import ReplayRecorder, replay_stepwise
from modules.scenario import IPCScenario


def test_scenario_save_load(tmp_path):
    scenario = IPCScenario(name="lab1", message_count=4, tamper_ciphertext=True)
    p = tmp_path / "scenario.json"
    scenario.save(p)
    loaded = IPCScenario.load(p)
    assert loaded.name == "lab1"
    assert loaded.message_count == 4
    assert loaded.tamper_ciphertext is True


def test_replay_recorder_roundtrip(tmp_path):
    recorder = ReplayRecorder()
    recorder.record({"action": "send"})
    recorder.record({"action": "recv"})
    p = tmp_path / "events.json"
    recorder.save(p)
    loaded = recorder.load(p)
    assert [e["action"] for e in replay_stepwise(loaded)] == ["send", "recv"]


def test_plugin_registry_runs():
    assert {"pipe", "queue", "shared_memory"}.issubset(set(list_plugins()))
    plugin = get_plugin("pipe")
    logs, events = plugin.run(scenario=IPCScenario(message_count=1))
    assert isinstance(logs, str)
    assert isinstance(events, list)
