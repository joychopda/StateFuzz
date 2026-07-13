from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Turn:
    index: int
    request: dict
    response: dict | None
    latency: float
    error: str | None = None


@dataclass
class SessionState:
    session_id: str | None = None
    protocol_version: str | None = None
    server_capabilities: dict = field(default_factory=dict)
    turns: list[Turn] = field(default_factory=list)
    custom: dict[str, Any] = field(default_factory=dict)


class StateTracker:
    """Tracks everything observed across a single fuzzing campaign so that
    detectors can reason about how the server's state evolves turn-over-turn,
    not just about one isolated request/response pair."""

    def __init__(self) -> None:
        self.state = SessionState()

    def record_init(self, session_id: str | None, protocol_version: str | None, capabilities: dict) -> None:
        self.state.session_id = session_id
        self.state.protocol_version = protocol_version
        self.state.server_capabilities = capabilities

    def record_turn(self, turn: Turn) -> None:
        self.state.turns.append(turn)

    def add_marker(self, marker: str) -> None:
        self.state.custom.setdefault("injected_markers", []).append(marker)
