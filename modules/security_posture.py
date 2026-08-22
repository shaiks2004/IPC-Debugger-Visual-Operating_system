from __future__ import annotations

from .scenario import IPCScenario


def evaluate_security_posture(scenario: IPCScenario) -> dict:
    integrity = not scenario.tamper_ciphertext
    authentication = not scenario.key_mismatch
    replay_protection = not scenario.replay_attack
    availability = not (scenario.drop_packet or scenario.race_condition)

    return {
        "confidentiality": True,
        "integrity": integrity,
        "authentication": authentication,
        "replay_protection": replay_protection,
        "availability": availability,
        "notes": [
            "Fernet provides confidentiality and authenticated encryption.",
            "Injected adversarial toggles intentionally degrade guarantees when enabled.",
        ],
    }
