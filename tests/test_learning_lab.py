from modules.learning_lab import (
    MissionScore,
    apply_lesson_to_scenario,
    apply_mission_to_scenario,
    build_backend_comparison_summary,
    build_cause_effect_trace,
    build_student_report,
    grade_quiz,
    infer_findings,
    score_debug_mission,
)
from modules.scenario import IPCScenario


def test_apply_lesson_and_mission_to_scenario():
    base = IPCScenario(name="x", tamper_ciphertext=False, replay_attack=False)
    lesson_sc = apply_lesson_to_scenario(base, "hmac_failure")
    mission_sc = apply_mission_to_scenario(base, "replay_hunter")

    assert lesson_sc.tamper_ciphertext is True
    assert lesson_sc.name.startswith("lesson-")
    assert mission_sc.replay_attack is True
    assert mission_sc.name.startswith("mission-")


def test_findings_trace_and_score():
    events = [
        {"action": "tamper_ciphertext", "hmac_ok": None, "replayed": False, "dropped": False},
        {"action": "recv", "hmac_ok": False, "replayed": False, "dropped": False},
        {"action": "auth_failed", "hmac_ok": False, "replayed": False, "dropped": False},
    ]
    findings = infer_findings(events)
    traces = build_cause_effect_trace(events)
    score = score_debug_mission("integrity_breach", events, elapsed_seconds=8, hints_used=1)

    assert "auth_failed" in findings
    assert traces
    assert isinstance(score, MissionScore)
    assert 0 <= score.total_score <= 100


def test_quiz_and_report_and_compare_rows():
    quiz = grade_quiz("hmac_failure", "auth_failed")
    assert quiz["correct"] is True

    scenario = IPCScenario(name="lab")
    events = [{"action": "replay", "replayed": True, "dropped": False, "hmac_ok": None}]
    report = build_student_report(
        scenario=scenario,
        backend="pipe",
        events=events,
        mission_score=None,
        quiz_results=[quiz],
    )
    assert report["backend"] == "pipe"
    assert "rubric" in report

    rows = build_backend_comparison_summary({"pipe": ("ok", events), "queue": ("ok", [])})
    assert len(rows) == 2
    assert rows[0]["backend"] in {"pipe", "queue"}
