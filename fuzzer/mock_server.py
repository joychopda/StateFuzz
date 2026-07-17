"""A deliberately vulnerable MCP-like target used only to exercise the
fuzzer end to end (see tests/). It has three real bugs, one per tool:

- kv.set: values are stored in one shared slot instead of being keyed
  per-request, so one call's data leaks into the next call's response
  regardless of key (exercised by sql_injection / cross-session tests).
- profile.update: assumes ``age`` is always an int and does arithmetic on
  it with no validation, so a schema-violating argument (wrong type,
  missing, oversized, deeply nested) crashes the handler instead of being
  cleanly rejected (exercised by the type_confusion plugin).
- resource.read: caches the *first* role it ever sees and treats that as
  the effective role for every subsequent caller regardless of user_id,
  instead of deriving authorization from the current call's identity every
  time (exercised by the identity_confusion plugin).
"""
from __future__ import annotations

from typing import Any

from aiohttp import web

_LAST_VALUE: dict[str, Any] = {"value": None}
_ROLE_CACHE: dict[str, Any] = {"role": None, "granted_to": None}


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

        if name == "profile.update":
            age = arguments["age"]  # bug: no type/presence validation at all
            new_age = age + 1  # crashes on anything that isn't an int
            return web.json_response(
                {"jsonrpc": "2.0", "id": req_id, "result": {"new_age": new_age}}
            )

        if name == "resource.read":
            user_id = arguments.get("user_id")
            role = arguments.get("role", "user")
            if _ROLE_CACHE["role"] is None:
                _ROLE_CACHE["role"] = role  # bug: cached once, never re-derived per caller
                _ROLE_CACHE["granted_to"] = user_id
            authorized = _ROLE_CACHE["role"] == "admin"
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "user_id": user_id,
                        "authorized": authorized,
                        "effective_role": _ROLE_CACHE["role"],
                        "originally_granted_to": _ROLE_CACHE["granted_to"],
                    },
                }
            )

        return web.json_response(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"unknown tool {name}"}}
        )

    return web.json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "unknown method"}})


def build_app() -> web.Application:
    # reset the module-global bug state so each test's server starts clean,
    # regardless of what earlier tests in the same process did to it
    _LAST_VALUE["value"] = None
    _ROLE_CACHE["role"] = None
    _ROLE_CACHE["granted_to"] = None

    app = web.Application()
    app.router.add_post("/mcp", handle)
    return app


if __name__ == "__main__":
    web.run_app(build_app(), port=8765)
