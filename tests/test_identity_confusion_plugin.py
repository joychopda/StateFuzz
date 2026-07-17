from aiohttp.test_utils import TestServer

from fuzzer.core.engine import FuzzEngine
from fuzzer.core.mutator import get_plugin
from fuzzer.core.transport import StreamableHTTPTransport
from fuzzer.mock_server import build_app


async def test_identity_confusion_catches_authorization_drift_across_identities():
    """mock_server.py's resource.read caches the *first* role it ever sees
    and treats that as the effective role for every subsequent caller,
    instead of re-deriving authorization from the current call's user_id.
    IdentityConfusionMutator establishes a legitimate admin grant for
    "alice" on turn 0, then swaps the identity on later turns — those
    later, never-legitimately-granted identities should still come back
    authorized as admin, proving the plugin surfaces real authorization
    drift across turns."""
    server = TestServer(build_app())
    await server.start_server()
    try:
        transport = StreamableHTTPTransport(str(server.make_url("/mcp")))
        engine = FuzzEngine(
            transport=transport,
            plugin=get_plugin("identity_confusion"),
            tool_name="resource.read",
            base_arguments={"user_id": "alice", "role": "admin"},
            detectors=[],
            max_turns=4,  # one full rotation through all 4 identity strategies
        )
        report = await engine.run_campaign()
    finally:
        await server.close()

    turns = engine.tracker.state.turns
    assert report.turns_run == 4

    baseline = turns[0].response["result"]
    assert baseline["user_id"] == "alice"
    assert baseline["authorized"] is True

    drifted = [
        t
        for t in turns[1:]
        if t.response is not None
        and t.response["result"]["user_id"] != "alice"
        and t.response["result"]["authorized"] is True
    ]
    assert drifted, (
        "expected at least one mutated (non-alice) identity to inherit admin "
        "authorization it never legitimately requested"
    )
