from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .core.cross_session import run_cross_session_campaign
from .core.detector import CrossTurnLeakDetector, LatencyDriftDetector, LatencyTrendDetector
from .core.engine import FuzzEngine
from .core.mutator import available_plugins, get_plugin
from .core.transport import StdioTransport, StreamableHTTPTransport, Transport


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stateful MCP server fuzzer")
    parser.add_argument(
        "--transport",
        choices=["http", "stdio"],
        default="http",
        help="Transport to speak to the target over (default: http)",
    )
    parser.add_argument(
        "--url",
        required=True,
        help=(
            "MCP endpoint, e.g. http://localhost:8765/mcp (--transport http), "
            "or the command to spawn the server, e.g. 'python -m my_mcp_server' (--transport stdio)"
        ),
    )
    parser.add_argument("--tool", required=True, help="Tool name to fuzz (tools/call target)")
    parser.add_argument("--arguments", default="{}", help="Base JSON arguments for the tool call")
    parser.add_argument("--plugin", default="sql_injection", choices=available_plugins())
    parser.add_argument("--turns", type=int, default=20)
    parser.add_argument("--delay", type=float, default=0.0, help="Seconds to sleep between turns")
    parser.add_argument(
        "--sessions",
        type=int,
        default=1,
        help=(
            "Number of independent sessions to run concurrently against the same server. "
            ">1 switches to cross-session mode: each session gets its own connection and "
            "marker namespace, and CrossSessionLeakDetector checks whether one session's "
            "marker resurfaces in another session's response (state shared across "
            "connections instead of scoped per session)."
        ),
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Extra HTTP header to send with every request, e.g. 'Authorization=Bearer token' "
        "(repeatable; only applies to --transport http)",
    )
    parser.add_argument("--out", default=None, help="Write the JSON report to this path")
    return parser.parse_args(argv)


def parse_headers(header_args: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in header_args:
        if "=" not in item:
            raise ValueError(f"invalid --header value {item!r}, expected KEY=VALUE")
        key, _, value = item.partition("=")
        if not key:
            raise ValueError(f"invalid --header value {item!r}, expected KEY=VALUE")
        headers[key] = value
    return headers


def build_transport(args: argparse.Namespace, headers: dict[str, str]) -> Transport:
    if args.transport == "stdio":
        return StdioTransport(args.url)
    return StreamableHTTPTransport(args.url, headers=headers)


async def _run(args: argparse.Namespace) -> int:
    try:
        base_arguments = json.loads(args.arguments)
    except json.JSONDecodeError as exc:
        print(f"error: --arguments is not valid JSON: {exc}", file=sys.stderr)
        return 2

    try:
        headers = parse_headers(args.header)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.sessions > 1:
        report = await run_cross_session_campaign(
            transport_factory=lambda: build_transport(args, headers),
            plugin_factory=lambda: get_plugin(args.plugin),
            tool_name=args.tool,
            base_arguments=base_arguments,
            turn_detectors=[CrossTurnLeakDetector(), LatencyDriftDetector(), LatencyTrendDetector()],
            num_sessions=args.sessions,
            turns_per_session=args.turns,
        )
    else:
        transport = build_transport(args, headers)
        plugin = get_plugin(args.plugin)
        detectors = [CrossTurnLeakDetector(), LatencyDriftDetector(), LatencyTrendDetector()]
        engine = FuzzEngine(
            transport=transport,
            plugin=plugin,
            tool_name=args.tool,
            base_arguments=base_arguments,
            detectors=detectors,
            max_turns=args.turns,
            delay=args.delay,
        )
        report = await engine.run_campaign()

    payload = json.dumps(report.to_dict(), indent=2, default=str)

    if args.out:
        with open(args.out, "w") as f:
            f.write(payload)
    print(payload)

    campaign_failed = bool(getattr(report, "campaign_error", None) or getattr(report, "campaign_errors", None))
    return 1 if report.findings or campaign_failed else 0


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
