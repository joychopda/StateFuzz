from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .session import StateTracker, Turn


@dataclass
class Finding:
    detector: str
    severity: str
    turn_index: int
    description: str
    evidence: dict = field(default_factory=dict)


class Detector(ABC):
    name: str

    @abstractmethod
    def analyze(self, tracker: StateTracker, turn: Turn) -> list[Finding]:
        """Inspect the latest turn (with full history available via tracker)
        and return zero or more findings."""


class CrossTurnLeakDetector(Detector):
    """Flags responses that contain a marker injected in an *earlier* turn.
    A well-isolated server should never let one call's payload resurface in
    a later, unrelated call's response — if it does, state is bleeding
    across turns (and, in a real deployment, potentially across sessions)."""

    name = "cross_turn_leak"

    def analyze(self, tracker: StateTracker, turn: Turn) -> list[Finding]:
        markers: list[str] = tracker.state.custom.get("injected_markers", [])
        if not turn.response or turn.index >= len(markers):
            return []

        current_marker = markers[turn.index]
        response_text = json.dumps(turn.response)
        findings: list[Finding] = []
        for prior_index, marker in enumerate(markers[: turn.index]):
            if marker != current_marker and marker in response_text:
                findings.append(
                    Finding(
                        detector=self.name,
                        severity="high",
                        turn_index=turn.index,
                        description=(
                            f"Turn {turn.index}'s response contains the marker injected in "
                            f"turn {prior_index}, indicating the server carried unisolated "
                            "state forward across tool calls."
                        ),
                        evidence={"leaked_marker": marker, "origin_turn": prior_index, "response": turn.response},
                    )
                )
        return findings


class LatencyDriftDetector(Detector):
    """Uses response latency as a cheap proxy for server-side resource growth.
    A monotonic blow-up relative to an early baseline is consistent with a
    per-session memory leak or an unbounded state structure accumulating
    across consecutive calls."""

    name = "latency_drift"

    def __init__(self, window: int = 5, ratio_threshold: float = 3.0) -> None:
        self.window = window
        self.ratio_threshold = ratio_threshold

    def analyze(self, tracker: StateTracker, turn: Turn) -> list[Finding]:
        turns = tracker.state.turns
        if len(turns) <= self.window:
            return []

        baseline = sum(t.latency for t in turns[: self.window]) / self.window
        if baseline <= 0:
            return []

        if turn.latency > baseline * self.ratio_threshold:
            return [
                Finding(
                    detector=self.name,
                    severity="medium",
                    turn_index=turn.index,
                    description=(
                        f"Turn {turn.index} latency ({turn.latency:.3f}s) is "
                        f"{turn.latency / baseline:.1f}x the first-{self.window}-turn baseline "
                        f"({baseline:.3f}s) — possible unbounded state growth across turns."
                    ),
                    evidence={"latency": turn.latency, "baseline": baseline},
                )
            ]
        return []
