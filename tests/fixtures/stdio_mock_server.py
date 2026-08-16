"""Tiny stdio MCP mock target used only by tests/test_stdio_transport.py.

Reads newline-delimited JSON-RPC 2.0 requests from stdin and writes
newline-delimited JSON-RPC 2.0 responses to stdout, exactly the contract
StdioTransport speaks. Its one tool, ``echo``, just echoes the arguments it
was given back in the result — enough to prove the transport itself (spawn,
handshake, request/response framing, shutdown) works end to end.
"""

from __future__ import annotations

import json
import sys


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request = json.loads(line)
        method = request.get("method")
        req_id = request.get("id")

        if method == "notifications/initialized":
            continue  # notification: no response expected

        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "stdio-echo-mock", "version": "0.1.0"},
                },
            }
        elif method == "tools/call":
            params = request.get("params", {})
            name = params.get("name")
            arguments = params.get("arguments", {})
            if name == "echo":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": "echo"}], "echoed": arguments},
                }
            elif name == "noisy_echo":
                # emits a spec-legal server notification (no "id") before the real
                # response, the way a server with logging/progress capabilities would
                sys.stdout.write(
                    json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info"}})
                    + "\n"
                )
                sys.stdout.flush()
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": "echo"}], "echoed": arguments},
                }
            elif name == "silent_drop":
                continue  # never responds, simulating a server that swallows the request
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"unknown tool {name}"},
                }
        else:
            response = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "unknown method"}}

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
