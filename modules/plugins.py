from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .scenario import IPCScenario
from .msg_queue_comm import secure_message_queue_example
from .pipe_comm import secure_pipe_example
from .shared_memory_comm import secure_shared_memory_example


@dataclass
class BackendPlugin:
    name: str
    runner: Callable

    def run(self, key=None, scenario: IPCScenario | None = None):
        return self.runner(key=key, scenario=scenario)


PLUGIN_REGISTRY = {
    "pipe": BackendPlugin("pipe", secure_pipe_example),
    "queue": BackendPlugin("queue", secure_message_queue_example),
    "shared_memory": BackendPlugin("shared_memory", secure_shared_memory_example),
}


def list_plugins() -> list[str]:
    return sorted(PLUGIN_REGISTRY.keys())


def get_plugin(name: str) -> BackendPlugin:
    return PLUGIN_REGISTRY[name]
