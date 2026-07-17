import sys
from pathlib import Path

from fuzzer.core.detector import CrossTurnLeakDetector, LatencyDriftDetector
from fuzzer.core.engine import FuzzEngine
from fuzzer.core.mutator import get_plugin
from fuzzer.core.transport import StdioTransport

FIXTURE = Path(__file__).parent / "fixtures" / "stdio_mock_server.py"


async def test_stdio_transport_drives_a_full_campaign():
    transport = StdioTransport(f"{sys.executable} {FIXTURE}")
    engine = FuzzEngine(
        transport=transport,
        plugin=get_plugin("sql_injection"),
        tool_name="echo",
        base_arguments={"key": "profile", "value": "trusted-default"},
        detectors=[CrossTurnLeakDetector(), LatencyDriftDetector(window=2)],
        max_turns=4,
    )
    report = await engine.run_campaign()

    assert report.turns_run == 4
    assert all(turn.error is None for turn in engine.tracker.state.turns)
    assert all(turn.response is not None and "result" in turn.response for turn in engine.tracker.state.turns)
    # the echoed arguments should carry the mutated, marker-tagged value back
    first_echoed = engine.tracker.state.turns[0].response["result"]["echoed"]
    assert "SFUZZ-" in first_echoed["value"]


async def test_stdio_transport_reports_error_for_unknown_tool():
    transport = StdioTransport(f"{sys.executable} {FIXTURE}")
    engine = FuzzEngine(
        transport=transport,
        plugin=get_plugin("sql_injection"),
        tool_name="does_not_exist",
        base_arguments={"key": "profile"},
        detectors=[],
        max_turns=1,
    )
    report = await engine.run_campaign()

    turn = engine.tracker.state.turns[0]
    assert turn.response is not None
    assert turn.response["error"]["message"] == "unknown tool does_not_exist"
    assert turn.error == "unknown tool does_not_exist"
    assert report.turns_run == 1
