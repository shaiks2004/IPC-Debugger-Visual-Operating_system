from __future__ import annotations

import json
from pathlib import Path


class ReplayRecorder:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, event: dict) -> None:
        self.events.append(event)

    def clear(self) -> None:
        self.events.clear()

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.events, indent=2), encoding="utf-8")

    def load(self, path: str | Path) -> list[dict]:
        self.events = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.events


def replay_stepwise(events: list[dict]):
    for event in events:
        yield event
