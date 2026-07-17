from __future__ import annotations

import asyncio
import json
import shlex
from abc import ABC, abstractmethod

import aiohttp

MCP_PROTOCOL_VERSION = "2025-03-26"


class Transport(ABC):
    session_id: str | None

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def initialize(self) -> dict | None: ...

    @abstractmethod
    async def send(self, request: dict) -> tuple[dict | None, str | None]: ...

    @abstractmethod
    async def close(self) -> None: ...


class StreamableHTTPTransport(Transport):
    """Client for the MCP "Streamable HTTP" transport (spec rev 2025-03-26):
    JSON-RPC 2.0 over POST, with the session pinned via the Mcp-Session-Id
    response header on the initialize call and echoed on every request after."""

    def __init__(self, url: str, headers: dict | None = None, timeout: float = 10.0) -> None:
        self.url = url
        self.session_id: str | None = None
        self._extra_headers = headers or {}
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._client: aiohttp.ClientSession | None = None
        self._next_id = 0

    async def connect(self) -> None:
        self._client = aiohttp.ClientSession(timeout=self._timeout)

    async def initialize(self) -> dict | None:
        request = {
            "jsonrpc": "2.0",
            "id": self._id(),
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "stateful-mcp-fuzzer", "version": "0.1.0"},
            },
        }
        result = await self._post(request)
        await self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect_body=False)
        return result

    async def send(self, request: dict) -> tuple[dict | None, str | None]:
        try:
            data = await self._post(request)
        except Exception as exc:  # a transport failure is itself fuzzing signal
            return None, str(exc)
        if data and "error" in data:
            return data, data["error"].get("message")
        return data, None

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    async def _post(self, payload: dict, expect_body: bool = True) -> dict | None:
        assert self._client is not None, "call connect() first"
        headers = {
            **self._extra_headers,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        async with self._client.post(self.url, json=payload, headers=headers) as resp:
            if self.session_id is None and "Mcp-Session-Id" in resp.headers:
                self.session_id = resp.headers["Mcp-Session-Id"]
            if not expect_body:
                return None
            body = await resp.text()
            if not body:
                return None
            if "text/event-stream" in resp.headers.get("Content-Type", ""):
                return self._parse_sse(body)
            return json.loads(body)

    @staticmethod
    def _parse_sse(body: str) -> dict | None:
        for line in body.splitlines():
            if line.startswith("data:"):
                return json.loads(line[len("data:"):].strip())
        return None


class StdioTransport(Transport):
    """Client for MCP servers exposed over stdio: spawns the server as a
    subprocess and speaks newline-delimited JSON-RPC 2.0 over its
    stdin/stdout, the transport most real local MCP servers actually use."""

    def __init__(self, command: str, timeout: float = 10.0) -> None:
        self.command = command
        self.session_id: str | None = None
        self._timeout = timeout
        self._process: asyncio.subprocess.Process | None = None
        self._next_id = 0

    async def connect(self) -> None:
        args = shlex.split(self.command)
        self._process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self.session_id = f"stdio-pid-{self._process.pid}"

    async def initialize(self) -> dict | None:
        request = {
            "jsonrpc": "2.0",
            "id": self._id(),
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "stateful-mcp-fuzzer", "version": "0.1.0"},
            },
        }
        result = await self._write_and_read(request)
        await self._write_and_read({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect_response=False)
        return result

    async def send(self, request: dict) -> tuple[dict | None, str | None]:
        try:
            data = await self._write_and_read(request)
        except Exception as exc:  # a transport failure is itself fuzzing signal
            return None, str(exc)
        if data and "error" in data:
            return data, data["error"].get("message")
        return data, None

    async def close(self) -> None:
        if self._process is None:
            return
        if self._process.stdin is not None:
            self._process.stdin.close()
        try:
            await asyncio.wait_for(self._process.wait(), timeout=self._timeout)
        except (asyncio.TimeoutError, ProcessLookupError):
            self._process.kill()
            await self._process.wait()

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    async def _write_and_read(self, payload: dict, expect_response: bool = True) -> dict | None:
        assert self._process is not None, "call connect() first"
        assert self._process.stdin is not None
        line = json.dumps(payload) + "\n"
        self._process.stdin.write(line.encode())
        await self._process.stdin.drain()

        if not expect_response:
            return None

        assert self._process.stdout is not None
        raw = await asyncio.wait_for(self._process.stdout.readline(), timeout=self._timeout)
        if not raw:
            raise RuntimeError("stdio transport: subprocess closed stdout before sending a response")
        return json.loads(raw.decode())
