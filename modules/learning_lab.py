from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .scenario import IPCScenario


LEARNING_PATHS = {
    "beginner": {
        "title": "Beginner",
        "outcomes": [
            "Understand secure message flow in IPC backends",
            "Recognize encryption, HMAC checks, and normal send/receive events",
        ],
        "lessons": ["hmac_failure", "key_mismatch"],
    },
    "intermediate": {
        "title": "Intermediate",
        "outcomes": [
            "Analyze backend differences under the same scenario",
            "Diagnose drop and race-condition symptoms from timeline events",
        ],
        "lessons": ["drop_packet", "race_condition"],
    },
    "security": {
        "title": "Security",
        "outcomes": [
            "Explain replay-attack behavior in IPC",
            "Understand integrity/authentication failures and defensive signals",
        ],
        "lessons": ["replay_attack", "shared_memory_leak"],
    },
}


LESSON_GUIDES = {
    "hmac_failure": {
        "goal": "Observe integrity failure when ciphertext is tampered.",
        "observe": "Look for tamper_ciphertext followed by auth_failed in events.",
        "success_criteria": "At least one auth_failed or decrypt_error event appears.",
        "checkpoints": [
            "Predict whether the receiver should decrypt successfully before running.",
            "Verify if HMAC status changes after tampering.",
        ],
        "scenario": {"tamper_ciphertext": True},
    },
    "shared_memory_leak": {
        "goal": "Understand plaintext exposure risks in shared memory channels.",
        "observe": "Compare shared-memory events with other backends and inspect packet flow.",
        "success_criteria": "Student explains why encryption-before-write is required.",
        "checkpoints": [
            "Predict what risk exists if encryption is removed.",
            "Identify where integrity verification happens on reads.",
        ],
        "scenario": {},
    },
    "replay_attack": {
        "goal": "Detect replay behavior in protocol traces.",
        "observe": "Find replay action and repeated recv/read fingerprint behavior.",
        "success_criteria": "At least one event has replayed=True.",
        "checkpoints": [
            "Predict whether replayed packets should be accepted.",
            "Identify replay flags in event timeline.",
        ],
        "scenario": {"replay_attack": True},
    },
    "key_mismatch": {
        "goal": "See what happens when sender/receiver keys do not match.",
        "observe": "Track decrypt_error or auth/decryption inconsistencies.",
        "success_criteria": "A decrypt_error event appears after recv/read.",
        "checkpoints": [
            "Predict if integrity can pass while decryption still fails.",
            "Explain why authenticity alone is not sufficient for decryption.",
        ],
        "scenario": {"key_mismatch": True},
    },
    "race_condition": {
        "goal": "Explore ordering/timing issues from race condition toggles.",
        "observe": "Check event ordering and waiting behavior across runs.",
        "success_criteria": "Student identifies timing-sensitive symptoms from trace order.",
        "checkpoints": [
            "Predict which side (sender/receiver) starts first.",
            "Explain why synchronization prevents flaky IPC outcomes.",
        ],
        "scenario": {"race_condition": True},
    },
    "drop_packet": {
        "goal": "Observe availability impact when packets are dropped.",
        "observe": "Find drop_packet action and reduced receive/decrypt events.",
        "success_criteria": "At least one event has dropped=True.",
        "checkpoints": [
            "Predict whether all messages will be delivered.",
            "Explain relationship between drop events and missing decrypts.",
        ],
        "scenario": {"drop_packet": True},
    },
}


DEBUG_MISSIONS = {
    "integrity_breach": {
        "title": "Mission 1: Integrity Breach",
        "prompt": "Find why receiver rejects packets and identify the security control that caught it.",
        "hints": [
            "Check event actions before auth_failed.",
            "Inspect HMAC status transitions.",
        ],
        "expected_findings": ["auth_failed", "tamper_ciphertext"],
        "scenario": {"tamper_ciphertext": True},
    },
    "replay_hunter": {
        "title": "Mission 2: Replay Hunter",
        "prompt": "Detect the replay symptom and state what metadata exposed it.",
        "hints": [
            "Look for duplicated encrypted payload behavior.",
            "Inspect replayed flags in timeline rows.",
        ],
        "expected_findings": ["replay"],
        "scenario": {"replay_attack": True},
    },
    "key_chaos": {
        "title": "Mission 3: Key Chaos",
        "prompt": "Explain why messages fail even when transport still works.",
        "hints": [
            "Compare authentication and decryption outcomes.",
            "Look for decrypt_error entries.",
        ],
        "expected_findings": ["decrypt_error"],
        "scenario": {"key_mismatch": True},
    },
}


QUIZ_BANK = {
    "hmac_failure": {
        "question": "Which event most directly indicates integrity enforcement worked?",
        "options": ["send", "auth_failed", "decrypt_ok", "write"],
        "answer": "auth_failed",
        "explanation": "auth_failed confirms modified ciphertext failed verification before decrypt.",
    },
    "replay_attack": {
        "question": "Which signal best indicates replay behavior in this lab?",
        "options": ["payload_size", "replayed=True", "cpu_sec", "sender_pid"],
        "answer": "replayed=True",
        "explanation": "The replayed flag tracks repeated packet fingerprint behavior.",
    },
    "mission": {
        "question": "Best first step in IPC debugging missions?",
        "options": [
            "Guess root cause immediately",
            "Inspect timeline cause→effect events",
            "Only check benchmark plot",
            "Ignore security posture",
        ],
        "answer": "Inspect timeline cause→effect events",
        "explanation": "Event ordering and security flags are the fastest way to localize IPC faults.",
    },
}


@dataclass
class MissionScore:
    mission_id: str
    correctness_points: int
    speed_points: int
    hint_penalty: int
    total_score: int
    findings: list[str]


def apply_lesson_to_scenario(scenario: IPCScenario, lesson_key: str) -> IPCScenario:
    guide = LESSON_GUIDES.get(lesson_key, {})
    overrides = guide.get("scenario", {})
    data = scenario.to_dict()
    data.update(overrides)
    data["name"] = f"lesson-{lesson_key}"
    return IPCScenario.from_dict(data)


def apply_mission_to_scenario(scenario: IPCScenario, mission_id: str) -> IPCScenario:
    mission = DEBUG_MISSIONS.get(mission_id, {})
    overrides = mission.get("scenario", {})
    data = scenario.to_dict()
    data.update(overrides)
    data["name"] = f"mission-{mission_id}"
    return IPCScenario.from_dict(data)


def infer_findings(events: list[dict]) -> list[str]:
    findings = set()
    for ev in events:
        action = str(ev.get("action", ""))
        if action:
            findings.add(action)
        if ev.get("replayed"):
            findings.add("replay")
        if ev.get("dropped"):
            findings.add("drop_packet")
        if ev.get("hmac_ok") is False:
            findings.add("auth_failed")
    return sorted(findings)


def build_cause_effect_trace(events: list[dict]) -> list[str]:
    traces: list[str] = []
    action_cause = {
        "tamper_ciphertext": "Ciphertext was modified",
        "auth_failed": "HMAC verification failed",
        "replay": "An old packet was resent",
        "decrypt_error": "Receiver could not decrypt packet with current key",
        "drop_packet": "Packet was intentionally dropped",
    }
    action_effect = {
        "tamper_ciphertext": "integrity check should fail before decrypt",
        "auth_failed": "payload is rejected to preserve integrity",
        "replay": "duplicate payload may be flagged as replayed",
        "decrypt_error": "message authenticity may pass but confidentiality fails",
        "drop_packet": "availability degrades and downstream receives may be missing",
    }

    for ev in events:
        action = str(ev.get("action", ""))
        if action in action_cause:
            traces.append(f"{action_cause[action]} -> {action_effect[action]}.")
        if action in {"recv", "read"} and ev.get("hmac_ok") is False:
            traces.append("Integrity check failed at receive/read -> packet was not trusted.")
        if ev.get("replayed"):
            traces.append("Repeated fingerprint detected -> replay risk increased.")

    if not traces:
        traces.append("No major fault signatures found; use timeline ordering to inspect normal flow.")
    return traces


def score_debug_mission(mission_id: str, events: list[dict], elapsed_seconds: float, hints_used: int) -> MissionScore:
    mission = DEBUG_MISSIONS.get(mission_id)
    expected = set(mission.get("expected_findings", [])) if mission else set()
    observed = set(infer_findings(events))

    if not expected:
        correctness_points = 0
    else:
        correctness_points = int(60 * (len(expected & observed) / len(expected)))

    speed_points = max(0, 30 - int(max(elapsed_seconds, 0) // 5))
    hint_penalty = min(max(hints_used, 0) * 8, 24)
    total_score = max(0, min(100, correctness_points + speed_points - hint_penalty + 10))

    return MissionScore(
        mission_id=mission_id,
        correctness_points=correctness_points,
        speed_points=speed_points,
        hint_penalty=hint_penalty,
        total_score=total_score,
        findings=sorted(observed),
    )


def grade_quiz(quiz_key: str, user_answer: str) -> dict:
    quiz = QUIZ_BANK.get(quiz_key) or QUIZ_BANK["mission"]
    expected = quiz["answer"].strip().lower()
    actual = (user_answer or "").strip().lower()
    correct = actual == expected
    feedback = "Correct." if correct else f"Not quite. Expected: {quiz['answer']}"
    return {
        "correct": correct,
        "feedback": feedback,
        "explanation": quiz["explanation"],
        "expected": quiz["answer"],
    }


def build_backend_comparison_summary(results: dict[str, tuple[str, list[dict]]]) -> list[dict]:
    rows: list[dict] = []
    for backend, (_logs, events) in sorted(results.items()):
        findings = infer_findings(events)
        rows.append(
            {
                "backend": backend,
                "events": len(events),
                "auth_failures": sum(1 for e in events if e.get("action") == "auth_failed"),
                "replays": sum(1 for e in events if e.get("replayed")),
                "drops": sum(1 for e in events if e.get("dropped")),
                "decrypt_errors": sum(1 for e in events if e.get("action") == "decrypt_error"),
                "findings": ", ".join(findings[:6]),
            }
        )
    return rows


def build_student_report(
    scenario: IPCScenario,
    backend: str,
    events: list[dict],
    mission_score: MissionScore | None,
    quiz_results: list[dict],
) -> dict:
    findings = infer_findings(events)
    trace = build_cause_effect_trace(events)
    rubric = {
        "diagnosis_quality": "Excellent" if mission_score and mission_score.total_score >= 85 else "Developing",
        "trace_reasoning": "Strong" if len(trace) >= 2 else "Needs support",
        "security_concepts": "Strong" if "auth_failed" in findings or "replay" in findings else "Developing",
    }

    return {
        "scenario": scenario.to_dict(),
        "backend": backend,
        "event_count": len(events),
        "errors_found": [f for f in findings if f in {"auth_failed", "decrypt_error", "drop_packet", "replay"}],
        "score": mission_score.total_score if mission_score else None,
        "score_breakdown": mission_score.__dict__ if mission_score else {},
        "cause_effect_trace": trace,
        "quiz_results": quiz_results,
        "rubric": rubric,
        "replay_trace": events,
    }


def export_student_report(report: dict, out_path: str | Path) -> Path:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path
