from fuzzer.core.detector import CrossSessionLeakDetector, CrossTurnLeakDetector
from fuzzer.core.session import StateTracker, Turn


def test_cross_turn_leak_detector_fires_when_earlier_marker_resurfaces():
    tracker = StateTracker()
    tracker.add_marker("SFUZZ-run0-0")
    tracker.add_marker("SFUZZ-run0-1")
    tracker.record_turn(Turn(index=0, request={}, response={"result": "clean"}, latency=0.01))

    leaking_turn = Turn(
        index=1,
        request={},
        response={"result": "previous value was SFUZZ-run0-0"},
        latency=0.01,
    )
    tracker.record_turn(leaking_turn)

    findings = CrossTurnLeakDetector().analyze(tracker, leaking_turn)

    assert len(findings) == 1
    assert findings[0].detector == "cross_turn_leak"
    assert findings[0].evidence["leaked_marker"] == "SFUZZ-run0-0"
    assert findings[0].evidence["origin_turn"] == 0


def test_cross_turn_leak_detector_silent_when_responses_are_isolated():
    tracker = StateTracker()
    tracker.add_marker("SFUZZ-run0-0")
    tracker.add_marker("SFUZZ-run0-1")
    tracker.record_turn(Turn(index=0, request={}, response={"result": "clean-0"}, latency=0.01))

    clean_turn = Turn(index=1, request={}, response={"result": "clean-1, no markers here"}, latency=0.01)
    tracker.record_turn(clean_turn)

    findings = CrossTurnLeakDetector().analyze(tracker, clean_turn)

    assert findings == []


def test_cross_turn_leak_detector_ignores_a_turns_own_marker():
    # a turn's response naturally often echoes back its own marker (e.g. an
    # echo tool) — that must not be mistaken for a leak from an earlier turn.
    tracker = StateTracker()
    tracker.add_marker("SFUZZ-run0-0")
    turn = Turn(index=0, request={}, response={"result": "SFUZZ-run0-0"}, latency=0.01)
    tracker.record_turn(turn)

    findings = CrossTurnLeakDetector().analyze(tracker, turn)

    assert findings == []


def test_cross_turn_leak_detector_silent_with_no_response():
    tracker = StateTracker()
    tracker.add_marker("SFUZZ-run0-0")
    turn = Turn(index=0, request={}, response=None, latency=0.01, error="connection reset")
    tracker.record_turn(turn)

    findings = CrossTurnLeakDetector().analyze(tracker, turn)

    assert findings == []


def test_cross_session_leak_detector_fires_across_independent_trackers():
    tracker_a = StateTracker()
    tracker_a.set_run_id("session0")
    tracker_a.add_marker("SFUZZ-session0-0")
    tracker_a.record_turn(Turn(index=0, request={}, response={"result": "ok-a"}, latency=0.01))

    tracker_b = StateTracker()
    tracker_b.set_run_id("session1")
    tracker_b.add_marker("SFUZZ-session1-0")
    leaking_turn = Turn(index=0, request={}, response={"result": "SFUZZ-session0-0 leaked in"}, latency=0.01)
    tracker_b.record_turn(leaking_turn)

    findings = CrossSessionLeakDetector().analyze([tracker_a, tracker_b])

    assert len(findings) == 1
    assert findings[0].detector == "cross_session_leak"
    assert findings[0].evidence["origin_session"] == 0
    assert findings[0].evidence["leaking_session"] == 1


def test_cross_session_leak_detector_silent_when_sessions_are_isolated():
    tracker_a = StateTracker()
    tracker_a.set_run_id("session0")
    tracker_a.add_marker("SFUZZ-session0-0")
    tracker_a.record_turn(Turn(index=0, request={}, response={"result": "ok-a"}, latency=0.01))

    tracker_b = StateTracker()
    tracker_b.set_run_id("session1")
    tracker_b.add_marker("SFUZZ-session1-0")
    tracker_b.record_turn(Turn(index=0, request={}, response={"result": "ok-b"}, latency=0.01))

    findings = CrossSessionLeakDetector().analyze([tracker_a, tracker_b])

    assert findings == []
