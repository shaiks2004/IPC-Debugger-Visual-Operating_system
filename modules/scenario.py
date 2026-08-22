from __future__ import annotations

from dataclasses import dataclass, asdict
import json
from pathlib import Path


@dataclass
class IPCScenario:
    name: str = "default"
    producers: int = 1
    consumers: int = 1
    message_count: int = 3
    message_size: int = 24
    interval_ms: int = 20
    tamper_ciphertext: bool = False
    replay_attack: bool = False
    key_mismatch: bool = False
    drop_packet: bool = False
    race_condition: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "IPCScenario":
        fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in fields}
        return cls(**filtered)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "IPCScenario":
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.from_dict(data)
