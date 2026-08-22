from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class ProtocolEvent:
    timestamp: str
    channel: str
    action: str
    sender_pid: int | None = None
    receiver_pid: int | None = None
    payload_size: int = 0
    hmac_ok: bool | None = None
    replayed: bool = False
    dropped: bool = False
    note: str = ""
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def now_ts() -> str:
    return datetime.now(timezone.utc).isoformat()
