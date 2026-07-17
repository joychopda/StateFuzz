from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field

from .detector import CrossSessionLeakDetector, Detector, Finding
from .engine import FuzzEngine
from .mutator import MutationPlugin
from .transport import Transport


@dataclass
class CrossSessionReport:
    tool: str
    plugin: str
    sessions_run: int
    turns_per_session: int
    findings: list[Finding] = field(default_factory=list)
    campaign_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "plugin": self.plugin,
            "sessions_run": self.sessions_run,
            "turns_per_session": self.turns_per_session,
            "campaign_errors": self.campaign_errors,
            "findings": [
                {
                    "detector": f.detector,
                    "severity": f.severity,
                    "turn_index": f.turn_index,
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
        }


async def run_cross_session_campaign(
    transport_factory: Callable[[], Transport],
    plugin_factory: Callable[[], MutationPlugin],
    tool_name: str,
    base_arguments: dict,
    turn_detectors: list[Detector],
    num_sessions: int = 3,
    turns_per_session: int = 10,
    concurrent: bool = True,
) -> CrossSessionReport:
    """Runs ``num_sessions`` independent fuzzing sessions against the same
    server (each with its own transport connection and marker namespace) and
    then checks whether any session's response surfaces a marker injected by
    a *different* session — direct proof of cross-session state bleed rather
    than the within-session bleed ``CrossTurnLeakDetector`` catches.

    Sessions run concurrently by default, mirroring independent real clients
    hitting the server at the same time. Set ``concurrent=False`` to run them
    strictly one after another (useful for deterministic tests against
    servers whose shared state is trivially last-write-wins)."""
    engines: list[FuzzEngine] = []
    for i in range(num_sessions):
        engine = FuzzEngine(
            transport=transport_factory(),
            plugin=plugin_factory(),
            tool_name=tool_name,
            base_arguments=base_arguments,
            detectors=turn_detectors,
            max_turns=turns_per_session,
        )
        engine.tracker.set_run_id(f"session{i}")
        engines.append(engine)

    if concurrent:
        campaign_reports = await asyncio.gather(*(engine.run_campaign() for engine in engines))
    else:
        campaign_reports = [await engine.run_campaign() for engine in engines]

    cross_session_findings = CrossSessionLeakDetector().analyze([engine.tracker for engine in engines])

    all_findings: list[Finding] = list(cross_session_findings)
    campaign_errors: list[str] = []
    for report in campaign_reports:
        all_findings.extend(report.findings)
        if report.campaign_error:
            campaign_errors.append(report.campaign_error)

    return CrossSessionReport(
        tool=tool_name,
        plugin=engines[0].plugin.name if engines else "",
        sessions_run=num_sessions,
        turns_per_session=turns_per_session,
        findings=all_findings,
        campaign_errors=campaign_errors,
    )
