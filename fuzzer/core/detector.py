from __future__ import annotations

import json
import statistics
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


class CrossSessionDetector(ABC):
    """Strategy interface for detectors that compare state across multiple
    *independent* sessions rather than across turns within a single session.
    Unlike ``Detector``, this runs once, after every session in a cross-session
    campaign has finished, with the full set of per-session trackers."""

    name: str

    @abstractmethod
    def analyze(self, trackers: list[StateTracker]) -> list[Finding]:
        """Inspect every session's recorded turns and return zero or more findings."""


class CrossSessionLeakDetector(CrossSessionDetector):
    """Flags a session whose response contains a marker injected by a
    *different*, independently-run session against the same server. A
    well-isolated server should never let one client's session data resurface
    in another client's session — if it does, state is shared across
    connections instead of being scoped per session (e.g. a process-global
    cache/slot instead of a per-session one)."""

    name = "cross_session_leak"

    def analyze(self, trackers: list[StateTracker]) -> list[Finding]:
        findings: list[Finding] = []
        for leaking_idx, leaking_tracker in enumerate(trackers):
            own_markers = set(leaking_tracker.state.custom.get("injected_markers", []))
            for turn in leaking_tracker.state.turns:
                if not turn.response:
                    continue
                response_text = json.dumps(turn.response)
                for origin_idx, origin_tracker in enumerate(trackers):
                    if origin_idx == leaking_idx:
                        continue
                    for marker in origin_tracker.state.custom.get("injected_markers", []):
                        if marker in own_markers or marker not in response_text:
                            continue
                        findings.append(
                            Finding(
                                detector=self.name,
                                severity="critical",
                                turn_index=turn.index,
                                description=(
                                    f"Session {leaking_idx}'s turn {turn.index} response contains a "
                                    f"marker injected by independent session {origin_idx}, indicating "
                                    "the server shares state across sessions instead of scoping it "
                                    "per session."
                                ),
                                evidence={
                                    "leaked_marker": marker,
                                    "leaking_session": leaking_idx,
                                    "origin_session": origin_idx,
                                    "response": turn.response,
                                },
                            )
                        )
        return findings


class LatencyDriftDetector(Detector):
    """Uses response latency as a cheap proxy for server-side resource growth.
    Baselines mean *and* stddev of the first ``window`` turns, then flags a
    later turn only if it clears both:
      1. ``mean + k * stddev`` — a statistically meaningful outlier relative
         to the baseline's own variance, not a flat multiple of the mean
         (which false-positives on servers whose latency is naturally noisy
         but not actually leaking).
      2. an absolute floor (``floor_seconds``) — so a baseline with near-zero
         latency and near-zero stddev doesn't flag routine jitter of a few
         milliseconds as a "leak" just because it's technically several
         stddevs above ~0.

    This catches a sharp, single-turn blow-up. It does *not* catch a slow,
    steady leak where every turn is only marginally slower than the last —
    that's what ``LatencyTrendDetector`` is for."""

    name = "latency_drift"

    def __init__(self, window: int = 5, k: float = 4.0, floor_seconds: float = 0.05) -> None:
        self.window = window
        self.k = k
        self.floor_seconds = floor_seconds

    def analyze(self, tracker: StateTracker, turn: Turn) -> list[Finding]:
        turns = tracker.state.turns
        if len(turns) <= self.window:
            return []

        baseline_latencies = [t.latency for t in turns[: self.window]]
        mean = statistics.fmean(baseline_latencies)
        stddev = statistics.pstdev(baseline_latencies) if len(baseline_latencies) > 1 else 0.0
        threshold = mean + self.k * stddev

        if turn.latency > threshold and turn.latency > self.floor_seconds:
            return [
                Finding(
                    detector=self.name,
                    severity="medium",
                    turn_index=turn.index,
                    description=(
                        f"Turn {turn.index} latency ({turn.latency:.3f}s) exceeds the first-"
                        f"{self.window}-turn baseline (mean={mean:.3f}s, stddev={stddev:.3f}s) by "
                        f"more than {self.k}x stddev (threshold={threshold:.3f}s) — possible "
                        "unbounded state growth across turns."
                    ),
                    evidence={
                        "latency": turn.latency,
                        "baseline_mean": mean,
                        "baseline_stddev": stddev,
                        "threshold": threshold,
                    },
                )
            ]
        return []


def _linear_regression(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """Ordinary least-squares slope and r-squared for a simple linear fit,
    with no numpy dependency since this is the only place that'd need it."""
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    ss_xy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    ss_xx = sum((x - mean_x) ** 2 for x in xs)
    ss_yy = sum((y - mean_y) ** 2 for y in ys)

    if ss_xx == 0:
        return 0.0, 0.0
    slope = ss_xy / ss_xx
    r_squared = 0.0 if ss_yy == 0 else (ss_xy**2) / (ss_xx * ss_yy)
    return slope, r_squared


class LatencyTrendDetector(Detector):
    """Complementary to ``LatencyDriftDetector``: fits a simple linear
    regression of latency against turn index across the *entire* turn
    history and flags a sustained, statistically confident upward trend.

    ``LatencyDriftDetector`` only compares one turn against an early
    baseline window, so it catches a sharp blow-up but misses a slow, steady
    leak where every turn is only marginally slower than the last — no
    single turn ever clears a stddev-based threshold, but the trend across
    the whole campaign is unmistakably upward. This detector exists
    specifically to catch that slow-leak case."""

    name = "latency_trend"

    def __init__(
        self, min_turns: int = 8, slope_threshold: float = 0.01, r_squared_threshold: float = 0.5
    ) -> None:
        self.min_turns = min_turns
        self.slope_threshold = slope_threshold
        self.r_squared_threshold = r_squared_threshold

    def analyze(self, tracker: StateTracker, turn: Turn) -> list[Finding]:
        turns = tracker.state.turns
        if len(turns) < self.min_turns:
            return []

        xs = [float(t.index) for t in turns]
        ys = [t.latency for t in turns]
        slope, r_squared = _linear_regression(xs, ys)

        if slope > self.slope_threshold and r_squared >= self.r_squared_threshold:
            return [
                Finding(
                    detector=self.name,
                    severity="medium",
                    turn_index=turn.index,
                    description=(
                        f"Latency shows a sustained upward trend across all {len(turns)} turns "
                        f"(slope={slope:.4f}s/turn, r²={r_squared:.2f}) — consistent with a "
                        "slow per-turn resource leak that a single-window baseline comparison "
                        "would miss."
                    ),
                    evidence={"slope": slope, "r_squared": r_squared, "turns": len(turns)},
                )
            ]
        return []
