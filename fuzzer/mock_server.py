"""A deliberately vulnerable MCP-like target used only to exercise the
fuzzer end to end (see tests/). Its single tool, kv.set, has a real bug:
values are stored in one shared slot instead of being keyed per-request, so
one call's data leaks into the next call's response regardless of key."""
from __future__ import annotations

from typing import Any

from aiohttp import web

_LAST_VALUE: dict[str, Any] = {"value": None}


async def handle(request: web.Request) -> web.Response:
    body = await request.json()
    method = body.get("method")
    req_id = body.get("id")

    if method == "initialize":
        return web.json_response(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "vulnerable-kv-mock", "version": "0.1.0"},
                },
            },
            headers={"Mcp-Session-Id": "mock-session-0001"},
        )

    if method == "notifications/initialized":
        return web.Response(status=202)

    if method == "tools/call":
        params = body.get("params", {})
        name = params.get("name")
        arguments = params.get("arguments", {})

        if name == "kv.set":
            key = arguments.get("key")
            value = arguments.get("value")
            previous_value = _LAST_VALUE["value"]
            _LAST_VALUE["value"] = value  # bug: no per-key isolation
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"stored key={key}"}],
                        "previous_value": previous_value,
                    },
                }
            )

        return web.json_response(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"unknown tool {name}"}}
        )

    return web.json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "unknown method"}})


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/mcp", handle)
    return app


if __name__ == "__main__":
    web.run_app(build_app(), port=8765)
