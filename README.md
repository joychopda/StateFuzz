# StateFuzz

[![CI](https://github.com/joychopda/StateFuzz/actions/workflows/ci.yml/badge.svg)](https://github.com/joychopda/StateFuzz/actions/workflows/ci.yml)

**Multi-turn, session-aware fuzzer for Model Context Protocol (MCP) servers.**

## The gap this fills

Every popular LLM/agent security scanner today — [promptfoo](https://github.com/promptfoo/promptfoo),
[garak](https://github.com/leondz/garak), static MCP tool-manifest scanners — evaluates
one request/response pair in isolation. Send a payload, inspect the reply, move on.

That model is blind to an entire class of real bugs: **state a server carries
*across* consecutive tool calls within a session.** MCP servers aren't
stateless request handlers — they hold session IDs, per-connection caches,
conversation buffers, and permission context that accumulate turn over turn.
Bugs live in that accumulation:

- A cache keyed wrong, so client A's data resurfaces in client B's response.
- A buffer that grows unbounded per session until the process falls over.
- Authorization state that drifts after a specific sequence of calls (grant,
  revoke, retry) instead of being re-checked every time.

None of these show up in a single request/response check. They only show up
if something is actually *watching the session evolve*.

## What StateFuzz does differently

| | Single-turn scanners (promptfoo, garak) | Static MCP manifest scanners | **StateFuzz** |
|---|---|---|---|
| Drives a real MCP session (`initialize` → session ID → N `tools/call`s) | No | No | **Yes** |
| Judges based on one response | Yes | N/A (no traffic) | No — judges the **accumulated session history** |
| Can catch state bleeding *within* one session, across turns | No | No | **Yes** (`cross_turn_leak`) |
| Can catch state bleeding *across* independent sessions | No | No | **Yes** (`cross_session_leak`, via `--sessions N`) |
| Can catch unbounded per-session memory growth | No | No | **Yes** (`latency_drift`, `latency_trend`) |
| Extending detection strategy | Fork the tool | Fork the tool | Drop a file in `fuzzer/plugins/`, no other changes |
| Proven against a real bug over real HTTP traffic | — | — | **Yes** — end-to-end test hits a genuinely buggy live server |

Concretely, the cool parts:

- **Real session-pinned transport, not a mock.** `StreamableHTTPTransport`
  speaks the actual MCP Streamable HTTP handshake (`initialize` → capture the
  `Mcp-Session-Id` response header → `notifications/initialized` → pin that
  ID on every following call). It's the same session a real client would
  hold open, so whatever the server does with that session — for better or
  worse — is exactly what gets fuzzed. `StdioTransport` speaks the same
  handshake over a spawned subprocess's stdin/stdout instead, since most
  real-world local MCP servers run over stdio, not HTTP.
- **Marker-based leak detection, not guessing from response shape.** Every
  mutated turn gets a unique, unforgeable marker
  (`SFUZZ-<run_id>-<turn_index>`) baked into its arguments.
  `CrossTurnLeakDetector` then checks whether a *later* turn's response, in
  the *same* session, ever contains a marker from an *earlier* turn. If it
  does, that's not a heuristic guess — it's direct proof the server let one
  call's data bleed into another within the same session.
- **Cross-session leak detection, not just cross-turn.** `--sessions N`
  (N > 1) runs N fully independent sessions concurrently against the same
  server — separate connections, separate marker namespaces.
  `CrossSessionLeakDetector` then checks whether *any* session's response
  contains a marker injected by a *different* session — direct proof of a
  process-global slot or connection-unscoped cache, the more severe bug
  class the README used to just assert without a code path to prove it.
- **Latency as a memory-leak proxy, without flat-multiple false positives.**
  `LatencyDriftDetector` baselines the mean *and* stddev of the first few
  turns and only flags a turn that clears both `mean + k*stddev` and an
  absolute floor — so jitter on a fast server doesn't trigger noise the way
  a flat `mean * 3` threshold would. `LatencyTrendDetector` complements it
  with a linear-regression slope across the *entire* turn history, catching
  a slow, steady leak that never produces one outlier turn but is
  unmistakable in aggregate. Neither requires server-side instrumentation.
- **Zero-friction extensibility.** New mutation strategy → subclass
  `MutationPlugin`, add `@register`, drop the file in `fuzzer/plugins/`. The
  loader (`pkgutil.iter_modules`) finds it automatically — it's immediately
  available via `--plugin <name>` on the CLI.
- **Honest end-to-end proof, not a mocked unit test.** `tests/` spins up a
  small aiohttp server with a *real* bug (`kv.set` writes to one shared slot
  instead of keying by request), runs a full fuzzing campaign against it over
  actual HTTP, and asserts the fuzzer catches the leak — proving the
  detection logic works against real request/response traffic, not just
  against contrived in-memory objects.

## Architecture

```
fuzzer/
├── core/
│   ├── transport.py      # Transport ABC + StreamableHTTPTransport (HTTP/JSON-RPC) + StdioTransport (subprocess)
│   ├── session.py        # SessionState / StateTracker — one session's memory
│   ├── mutator.py        # MutationPlugin ABC + self-registering plugin loader
│   ├── detector.py       # Detector/CrossSessionDetector ABCs + CrossTurnLeakDetector,
│   │                     # CrossSessionLeakDetector, LatencyDriftDetector
│   ├── engine.py         # FuzzEngine — orchestrates one session's campaign turn by turn
│   └── cross_session.py  # runs N independent FuzzEngine sessions, then diffs their trackers
├── plugins/
│   ├── sql_injection_mutator.py        # SQLi-style payload append + marker tagging
│   ├── type_confusion_mutator.py       # boundary/type-confusion: schema validation probing
│   └── identity_confusion_mutator.py   # session/identity-confusion: authorization drift probing
├── mock_server.py     # deliberately vulnerable target used by tests/
└── cli.py             # `mcp-fuzz` entry point
```

**Extending it:**
- New mutation strategy → drop a file in `fuzzer/plugins/`, subclass
  `MutationPlugin`, decorate with `@register`. It's picked up automatically
  (`--plugin <name>` on the CLI) — no other file needs to change.
- New detector → subclass `Detector`, add it to the `detectors` list passed
  into `FuzzEngine` (currently wired in `cli.py`).
- New transport (e.g. WebSocket) → subclass `Transport`. `StreamableHTTPTransport`
  and `StdioTransport` are the two that exist today, selectable via
  `--transport {http,stdio}`.

**How state tracking works:** `StateTracker` holds one session's full turn
history (request, response, latency, error) plus a `custom` scratch dict that
plugins/detectors share. `SQLInjectionMutator` tags every turn with a unique
marker string (`SFUZZ-<run_id>-<turn_index>`); `CrossTurnLeakDetector` then
checks whether a later turn's response, within that same session, contains a
marker from an *earlier* turn in that session — a direct signal that the
server is leaking state across calls instead of isolating them.

**How cross-session testing works:** `--sessions N` (N > 1) hands off to
`run_cross_session_campaign`, which spins up N independent `FuzzEngine`
instances — each with its own transport connection and its own `StateTracker`
(`run_id` set to `session0`, `session1`, ... so markers can't collide even if
the server reuses the same session id for every connection). All N sessions
run concurrently by default. Once every session finishes,
`CrossSessionLeakDetector` scans every session's turns for a marker that
originated in a *different* session's tracker — proof that state leaked
across independent connections, not just across turns in one session.

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

Cross-session mode — runs N independent sessions concurrently against the
same server and checks whether one session's marker resurfaces in another's
response (this is what actually catches `kv.set`'s process-global slot bug):

```bash
python -m fuzzer.cli \
  --url http://localhost:8765/mcp \
  --tool kv.set \
  --arguments '{"key": "profile", "value": "trusted-default"}' \
  --sessions 3 --turns 5
```

Against a local stdio MCP server — `--url` becomes the command to spawn:

```bash
python -m fuzzer.cli \
  --transport stdio \
  --url "python -m my_local_mcp_server" \
  --tool some_tool \
  --arguments '{"...": "..."}' \
  --turns 10
```

Against a real target (most non-trivial servers require auth — `--header` is
repeatable, so pass as many as the server needs):

```bash
python -m fuzzer.cli --url https://your-mcp-server/mcp --tool <tool_name> \
  --arguments '{"...": "..."}' --plugin sql_injection --turns 50 \
  --header "Authorization=Bearer $MCP_TOKEN" --out report.json
```

Exit code is `1` if any finding was raised, `0` otherwise (CI-friendly).

## Tests

```bash
python -m pytest tests/ -v
```

Linting, formatting, and type checking (same checks CI runs, via `.github/workflows/ci.yml`):

```bash
ruff check .
ruff format --check .
mypy
```

The end-to-end tests spin up the intentionally-buggy mock server (which
stores every `kv.set` value in one shared slot instead of keying by
request), run real campaigns against it over HTTP, and assert:
- `CrossTurnLeakDetector` flags the leak within a single session
  (`tests/test_fuzzer_end_to_end.py`), and
- `CrossSessionLeakDetector` flags the same underlying bug across two
  independent sessions (`tests/test_cross_session.py`)

both proving the detection logic works against real request/response
traffic, not just in unit isolation.

## Mutation plugins (current)

| Plugin | Strategy | Probes for |
|---|---|---|
| `sql_injection` | appends a rotating SQLi payload to every string argument; tags each turn with a unique marker | shared/leaked state (via the marker, read by `cross_turn_leak`/`cross_session_leak`) |
| `type_confusion` | rotates one argument per turn through: type swap, dropped key, injected null, oversized string, deeply nested object | schema/input validation — a handler that trusts its declared types instead of checking them tends to crash or misbehave |
| `identity_confusion` | finds an argument that looks like a session/user/account id and rotates it through: unmodified baseline, a different identity, a numeric neighbor, a privileged sentinel (`admin`, `root`, ...) | authorization drift — state/decisions that should be re-derived from the current identity every call but instead persist across identities |

`--plugin <name>` selects one on the CLI; `available_plugins()` (backed by
the self-registering `@register` loader) is what feeds its `choices`.

## Detectors (current)

| Detector | Scope | Signal | Catches |
|---|---|---|---|
| `cross_turn_leak` | within one session | earlier turn's marker resurfaces in a later response, same session | shared/unisolated per-session state |
| `cross_session_leak` | across N independent sessions (`--sessions N`) | one session's marker resurfaces in a *different* session's response | process-global or connection-unscoped state |
| `latency_drift` | within one session | a turn's latency exceeds `mean + k*stddev` of an early baseline window, and an absolute floor | unbounded per-session state growth / memory leaks (sharp blow-up) |
| `latency_trend` | within one session | linear-regression slope of latency vs. turn index across the whole history is positive and confident (r²) | the same, but a slow steady leak with no single outlier turn |

## Roadmap

- Multi-tool "turn plan" campaigns (fuzz a *sequence* across different tools,
  not just one tool repeated)
- `CapabilityDriftDetector` — re-issue `tools/list` mid-campaign and diff
  against what was advertised at `initialize`
- `context_window_overflow_mutator` — grow an argument turn over turn and
  detect silent truncation/drop behavior
- WebSocket transport (Streamable HTTP and stdio are implemented)

## Status

Actively developed. See `git log` for current state and history.
