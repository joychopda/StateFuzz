from aiohttp.test_utils import TestServer

from fuzzer.core.transport import StdioTransport, StreamableHTTPTransport
from fuzzer.mock_server import build_app


async def test_streamable_http_transport_happy_path_captures_session_id():
    server = TestServer(build_app())
    await server.start_server()
    try:
        transport = StreamableHTTPTransport(str(server.make_url("/mcp")))
        await transport.connect()
        try:
            init_result = await transport.initialize()
            assert init_result["result"]["serverInfo"]["name"] == "vulnerable-kv-mock"
            assert transport.session_id == "mock-session-0001"

            response, error = await transport.send(
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/call",
                    "params": {"name": "kv.set", "arguments": {"key": "a", "value": "b"}},
                }
            )
            assert error is None
            assert response["result"]["content"][0]["text"] == "stored key=a"
        finally:
            await transport.close()
    finally:
        await server.close()


async def test_streamable_http_transport_send_reports_connection_refused_without_raising():
    # nothing is listening on this port, so the request should fail at the
    # socket level — send() must catch that and hand back an error tuple
    # instead of letting the exception escape.
    transport = StreamableHTTPTransport("http://127.0.0.1:1/mcp", timeout=1.0)
    await transport.connect()
    try:
        response, error = await transport.send({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}})
    finally:
        await transport.close()

    assert response is None
    assert error is not None


async def test_stdio_transport_close_is_safe_without_connect():
    transport = StdioTransport("does-not-matter")

    await transport.close()  # must not raise even though connect() was never called


async def test_stdio_transport_connect_failure_raises_for_a_nonexistent_command():
    transport = StdioTransport("this-command-does-not-exist-anywhere")

    try:
        raised = False
        try:
            await transport.connect()
        except FileNotFoundError:
            raised = True
        assert raised, "expected connect() to surface the spawn failure rather than swallow it"
    finally:
        await transport.close()
