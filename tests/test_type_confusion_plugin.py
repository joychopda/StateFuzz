from aiohttp.test_utils import TestServer

from fuzzer.core.engine import FuzzEngine
from fuzzer.core.mutator import get_plugin
from fuzzer.core.transport import StreamableHTTPTransport
from fuzzer.mock_server import build_app


async def test_type_confusion_crashes_the_unvalidated_profile_update_handler():
    """mock_server.py's profile.update assumes `age` is always an int and does
    arithmetic on it with zero validation. Every TypeConfusionMutator strategy
    (type swap, dropped key, null, oversized string, deep nesting) should
    break that assumption and crash the handler instead of getting a clean
    tools/call error back — proving the plugin actually surfaces a real
    input-validation bug, not just sending noise."""
    server = TestServer(build_app())
    await server.start_server()
    try:
        transport = StreamableHTTPTransport(str(server.make_url("/mcp")))
        engine = FuzzEngine(
            transport=transport,
            plugin=get_plugin("type_confusion"),
            tool_name="profile.update",
            base_arguments={"age": 30},
            detectors=[],
            max_turns=5,  # one full rotation through all 5 strategies
        )
        report = await engine.run_campaign()
    finally:
        await server.close()

    turns = engine.tracker.state.turns
    assert report.turns_run == 5
    crashed_turns = [t for t in turns if t.error is not None]
    assert crashed_turns, "expected at least one schema-violating mutation to crash the fragile handler"
