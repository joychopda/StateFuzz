from aiohttp.test_utils import TestServer

from fuzzer.core.cross_session import run_cross_session_campaign
from fuzzer.core.detector import CrossTurnLeakDetector, LatencyDriftDetector
from fuzzer.core.mutator import get_plugin
from fuzzer.core.transport import StreamableHTTPTransport
from fuzzer.mock_server import build_app


async def test_cross_session_detector_catches_global_shared_slot():
    """mock_server.py's kv.set writes to one process-global slot instead of a
    per-session one. Two independent sessions hitting it should leak markers
    across each other, which is exactly the class of bug CrossSessionLeakDetector
    exists to catch (as distinct from CrossTurnLeakDetector's within-session check)."""
    server = TestServer(build_app())
    await server.start_server()
    try:
        url = str(server.make_url("/mcp"))
        report = await run_cross_session_campaign(
            transport_factory=lambda: StreamableHTTPTransport(url),
            plugin_factory=lambda: get_plugin("sql_injection"),
            tool_name="kv.set",
            base_arguments={"key": "profile", "value": "trusted-default"},
            turn_detectors=[CrossTurnLeakDetector(), LatencyDriftDetector(window=2)],
            num_sessions=2,
            turns_per_session=3,
            concurrent=False,  # deterministic: session 0 fully completes, then session 1 starts
        )
    finally:
        await server.close()

    cross_session_leaks = [f for f in report.findings if f.detector == "cross_session_leak"]
    assert cross_session_leaks, "expected CrossSessionLeakDetector to catch the global shared-slot bug"
    assert cross_session_leaks[0].evidence["origin_session"] == 0
    assert cross_session_leaks[0].evidence["leaking_session"] == 1


async def test_cross_session_detector_silent_when_sessions_are_isolated():
    """Sanity check: independent StateTrackers with disjoint markers and no
    shared response text must not produce any cross-session findings."""
    from fuzzer.core.detector import CrossSessionLeakDetector
    from fuzzer.core.session import StateTracker, Turn

    tracker_a = StateTracker()
    tracker_a.set_run_id("session0")
    tracker_a.add_marker("SFUZZ-session0-0")
    tracker_a.record_turn(Turn(index=0, request={}, response={"result": "ok-a"}, latency=0.01))

    tracker_b = StateTracker()
    tracker_b.set_run_id("session1")
    tracker_b.add_marker("SFUZZ-session1-0")
    tracker_b.record_turn(Turn(index=0, request={}, response={"result": "ok-b"}, latency=0.01))

    findings = CrossSessionLeakDetector().analyze([tracker_a, tracker_b])
    assert findings == []
