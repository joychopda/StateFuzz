from aiohttp.test_utils import TestServer

from fuzzer.core.detector import CrossTurnLeakDetector, LatencyDriftDetector
from fuzzer.core.engine import FuzzEngine
from fuzzer.core.mutator import get_plugin
from fuzzer.core.transport import StreamableHTTPTransport
from fuzzer.mock_server import build_app


async def test_fuzzer_detects_cross_turn_state_leak():
    server = TestServer(build_app())
    await server.start_server()
    try:
        transport = StreamableHTTPTransport(str(server.make_url("/mcp")))
        engine = FuzzEngine(
            transport=transport,
            plugin=get_plugin("sql_injection"),
            tool_name="kv.set",
            base_arguments={"key": "profile", "value": "trusted-default"},
            detectors=[CrossTurnLeakDetector(), LatencyDriftDetector(window=2)],
            max_turns=5,
        )
        report = await engine.run_campaign()
    finally:
        await server.close()

    leaks = [f for f in report.findings if f.detector == "cross_turn_leak"]
    assert leaks, "expected the fuzzer to catch the mock server's shared-slot state bug"
    assert leaks[0].turn_index >= 1
