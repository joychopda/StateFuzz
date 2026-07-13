from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .core.detector import CrossTurnLeakDetector, LatencyDriftDetector
from .core.engine import FuzzEngine
from .core.mutator import available_plugins, get_plugin
from .core.transport import StreamableHTTPTransport


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stateful MCP server fuzzer")
    parser.add_argument("--url", required=True, help="MCP endpoint, e.g. http://localhost:8765/mcp")
    parser.add_argument("--tool", required=True, help="Tool name to fuzz (tools/call target)")
    parser.add_argument("--arguments", default="{}", help="Base JSON arguments for the tool call")
    parser.add_argument("--plugin", default="sql_injection", choices=available_plugins())
    parser.add_argument("--turns", type=int, default=20)
    parser.add_argument("--delay", type=float, default=0.0, help="Seconds to sleep between turns")
    parser.add_argument("--out", default=None, help="Write the JSON report to this path")
    return parser.parse_args(argv)


async def _run(args: argparse.Namespace) -> int:
    transport = StreamableHTTPTransport(args.url)
    plugin = get_plugin(args.plugin)
    detectors = [CrossTurnLeakDetector(), LatencyDriftDetector()]
    engine = FuzzEngine(
        transport=transport,
        plugin=plugin,
        tool_name=args.tool,
        base_arguments=json.loads(args.arguments),
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
    return 1 if report.findings else 0


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
