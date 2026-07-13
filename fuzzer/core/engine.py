from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from .detector import Detector, Finding
from .mutator import MutationPlugin
from .session import StateTracker, Turn
from .transport import Transport


@dataclass
class CampaignReport:
    tool: str
    plugin: str
    turns_run: int
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "plugin": self.plugin,
            "turns_run": self.turns_run,
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


class FuzzEngine:
    """Drives one fuzzing campaign: repeatedly calls a single MCP tool over
    a pinned session, mutating arguments each turn via the active plugin and
    running every detector against the growing session history."""

    def __init__(
        self,
        transport: Transport,
        plugin: MutationPlugin,
        tool_name: str,
        base_arguments: dict,
        detectors: list[Detector],
        max_turns: int = 20,
        delay: float = 0.0,
    ) -> None:
        self.transport = transport
        self.plugin = plugin
        self.tool_name = tool_name
        self.base_arguments = base_arguments
        self.detectors = detectors
        self.max_turns = max_turns
        self.delay = delay
        self.tracker = StateTracker()

    async def run_campaign(self) -> CampaignReport:
        await self.transport.connect()
        init_result = await self.transport.initialize()
        result = (init_result or {}).get("result", {})
        self.tracker.record_init(
            session_id=self.transport.session_id,
            protocol_version=result.get("protocolVersion"),
            capabilities=result.get("capabilities", {}),
        )

        findings: list[Finding] = []
        try:
            for i in range(self.max_turns):
                arguments = self.plugin.mutate(i, self.base_arguments, self.tracker)
                request = {
                    "jsonrpc": "2.0",
                    "id": i + 1,
                    "method": "tools/call",
                    "params": {"name": self.tool_name, "arguments": arguments},
                }

                start = time.monotonic()
                response, error = await self.transport.send(request)
                latency = time.monotonic() - start

                turn = Turn(index=i, request=request, response=response, latency=latency, error=error)
                self.tracker.record_turn(turn)

                for detector in self.detectors:
                    findings.extend(detector.analyze(self.tracker, turn))

                if self.delay:
                    await asyncio.sleep(self.delay)
        finally:
            await self.transport.close()

        return CampaignReport(
            tool=self.tool_name,
            plugin=self.plugin.name,
            turns_run=len(self.tracker.state.turns),
            findings=findings,
        )
