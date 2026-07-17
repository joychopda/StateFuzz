from fuzzer.core.session import StateTracker, Turn


def test_record_init_populates_session_state():
    tracker = StateTracker()

    tracker.record_init(
        session_id="sess-1",
        protocol_version="2025-03-26",
        capabilities={"tools": {}},
    )

    assert tracker.state.session_id == "sess-1"
    assert tracker.state.protocol_version == "2025-03-26"
    assert tracker.state.server_capabilities == {"tools": {}}
    assert tracker.state.turns == []


def test_record_init_with_no_session_id_leaves_it_none():
    tracker = StateTracker()

    tracker.record_init(session_id=None, protocol_version=None, capabilities={})

    assert tracker.state.session_id is None
    assert tracker.state.protocol_version is None


def test_record_turn_appends_in_order():
    tracker = StateTracker()
    turn0 = Turn(index=0, request={"a": 1}, response={"ok": True}, latency=0.01)
    turn1 = Turn(index=1, request={"a": 2}, response={"ok": True}, latency=0.02)

    tracker.record_turn(turn0)
    tracker.record_turn(turn1)

    assert tracker.state.turns == [turn0, turn1]
    assert [t.index for t in tracker.state.turns] == [0, 1]


def test_add_marker_preserves_insertion_order():
    tracker = StateTracker()

    tracker.add_marker("marker-a")
    tracker.add_marker("marker-b")
    tracker.add_marker("marker-c")

    assert tracker.state.custom["injected_markers"] == ["marker-a", "marker-b", "marker-c"]


def test_add_marker_on_a_fresh_tracker_creates_the_list():
    tracker = StateTracker()

    assert "injected_markers" not in tracker.state.custom
    tracker.add_marker("only-marker")
    assert tracker.state.custom["injected_markers"] == ["only-marker"]


def test_set_run_id_is_independent_of_session_id():
    tracker = StateTracker()
    tracker.record_init(session_id="server-assigned-id", protocol_version=None, capabilities={})

    tracker.set_run_id("client-assigned-run-id")

    assert tracker.state.run_id == "client-assigned-run-id"
    assert tracker.state.session_id == "server-assigned-id"
