# Stateful MCP Server Fuzzer

Multi-turn, session-aware fuzzer for Model Context Protocol (MCP) servers.
Single-turn scanners (promptfoo, garak) evaluate one request/response pair in
isolation and miss an entire class of bugs: state that a server carries
*across* consecutive tool calls within a session — shared caches, unbounded
per-session buffers, cross-request memory leaks, or authorization state that
drifts after a specific sequence of calls.

This tool drives a real MCP session over many turns, mutates arguments each
turn via a pluggable strategy, and runs detectors against the accumulated
session history (not just the latest response) to catch exactly that class
of bug.

## Architecture

```
fuzzer/
├── core/
│   ├── transport.py   # Transport ABC + StreamableHTTPTransport (MCP over HTTP/JSON-RPC)
│   ├── session.py     # SessionState / StateTracker — the campaign's memory
│   ├── mutator.py     # MutationPlugin ABC + self-registering plugin loader
│   ├── detector.py    # Detector ABC + CrossTurnLeakDetector, LatencyDriftDetector
│   └── engine.py      # FuzzEngine — orchestrates a campaign turn by turn
├── plugins/
│   └── sql_injection_mutator.py   # first mutation strategy
├── mock_server.py     # deliberately vulnerable target used by tests/
└── cli.py             # `mcp-fuzz` entry point
```

**Extending it:**
- New mutation strategy → drop a file in `fuzzer/plugins/`, subclass
  `MutationPlugin`, decorate with `@register`. It's picked up automatically
  (`--plugin <name>` on the CLI) — no other file needs to change.
- New detector → subclass `Detector`, add it to the `detectors` list passed
  into `FuzzEngine` (currently wired in `cli.py`).
- New transport (e.g. stdio, WebSocket) → subclass `Transport`.

**How state tracking works:** `StateTracker` holds the full turn history
(request, response, latency, error) plus a `custom` scratch dict that
plugins/detectors share. `SQLInjectionMutator` tags every turn with a unique
marker string; `CrossTurnLeakDetector` then checks whether a later turn's
response contains a marker from an *earlier* turn — a direct signal that the
server is leaking state across calls instead of isolating them.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

Against the bundled vulnerable mock target (for a live demo):

```bash
python -m fuzzer.mock_server &        # http://localhost:8765/mcp

python -m fuzzer.cli \
  --url http://localhost:8765/mcp \
  --tool kv.set \
  --arguments '{"key": "profile", "value": "trusted-default"}' \
  --turns 10
```

Against a real target:

```bash
python -m fuzzer.cli --url https://your-mcp-server/mcp --tool <tool_name> \
  --arguments '{"...": "..."}' --plugin sql_injection --turns 50 --out report.json
```

Exit code is `1` if any finding was raised, `0` otherwise (CI-friendly).

## Tests

```bash
python -m pytest tests/ -v
```

The end-to-end test spins up the intentionally-buggy mock server (which
stores every `kv.set` value in one shared slot instead of keying by
request), runs a real campaign against it over HTTP, and asserts the
fuzzer's `CrossTurnLeakDetector` actually flags the leak — proving the
detection logic works against real request/response traffic, not just in
unit isolation.

## Detectors (current)

| Detector | Signal | Catches |
|---|---|---|
| `cross_turn_leak` | earlier turn's marker resurfaces in a later response | shared/unisolated server-side state |
| `latency_drift` | response latency blows up vs. an early-turn baseline | unbounded per-session state growth / memory leaks |

## Status

MVP. See `instruction.md` for current state, decisions, and pending work.
