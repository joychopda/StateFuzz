from fuzzer.core.detector import Detector
from fuzzer.core.engine import FuzzEngine
from fuzzer.core.mutator import MutationPlugin
from fuzzer.core.transport import StreamableHTTPTransport, Transport


class _StubTransport(Transport):
    def __init__(self, fail_on_connect: bool = False, fail_on_initialize: bool = False) -> None:
        self.session_id: str | None = "stub-session"
        self._fail_on_connect = fail_on_connect
        self._fail_on_initialize = fail_on_initialize
        self.closed = False

    async def connect(self) -> None:
        if self._fail_on_connect:
            raise ConnectionError("connection refused")

    async def initialize(self) -> dict | None:
        if self._fail_on_initialize:
            raise ConnectionError("handshake failed")
        return {"result": {"protocolVersion": "2025-03-26", "capabilities": {}}}

    async def send(self, request: dict) -> tuple[dict | None, str | None]:
        return {"result": "ok"}, None

    async def close(self) -> None:
        self.closed = True


class _StubPlugin(MutationPlugin):
    name = "stub"

    def mutate(self, turn_index, base_arguments, tracker):
        return dict(base_arguments)


class _CountingDetector(Detector):
    name = "counting"

    def __init__(self) -> None:
        self.calls = 0

    def analyze(self, tracker, turn):
        self.calls += 1
        return []


async def test_engine_happy_path_runs_all_turns_and_invokes_detectors():
    transport = _StubTransport()
    detector = _CountingDetector()
    engine = FuzzEngine(
        transport=transport,
        plugin=_StubPlugin(),
        tool_name="noop",
        base_arguments={},
        detectors=[detector],
        max_turns=4,
    )

    report = await engine.run_campaign()

    assert report.turns_run == 4
    assert report.campaign_error is None
    assert detector.calls == 4
    assert transport.closed is True


async def test_engine_reports_campaign_error_instead_of_crashing_on_initialize_failure():
    transport = _StubTransport(fail_on_initialize=True)
    engine = FuzzEngine(
        transport=transport,
        plugin=_StubPlugin(),
        tool_name="noop",
        base_arguments={},
        detectors=[],
        max_turns=5,
    )

    report = await engine.run_campaign()  # must not raise

    assert report.turns_run == 0
    assert report.findings == []
    assert report.campaign_error is not None
    assert transport.closed is True, "transport must still be closed even after initialize() fails"


async def test_engine_reports_campaign_error_instead_of_crashing_on_connect_failure():
    transport = _StubTransport(fail_on_connect=True)
    engine = FuzzEngine(
        transport=transport,
        plugin=_StubPlugin(),
        tool_name="noop",
        base_arguments={},
        detectors=[],
        max_turns=5,
    )

    report = await engine.run_campaign()

    assert report.turns_run == 0
    assert report.campaign_error is not None


async def test_engine_completes_gracefully_when_server_refuses_the_connection():
    # true transport-failure test: nothing is listening on this port, so the
    # real StreamableHTTPTransport hits a connection error during
    # initialize() — the campaign must still complete and report it instead
    # of crashing the caller with an unhandled exception.
    transport = StreamableHTTPTransport("http://127.0.0.1:1/mcp", timeout=1.0)
    engine = FuzzEngine(
        transport=transport,
        plugin=_StubPlugin(),
        tool_name="noop",
        base_arguments={},
        detectors=[],
        max_turns=5,
    )

    report = await engine.run_campaign()

    assert report.turns_run == 0
    assert report.campaign_error is not None
    assert report.findings == []
