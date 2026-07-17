from fuzzer.core.detector import LatencyDriftDetector, LatencyTrendDetector
from fuzzer.core.session import StateTracker, Turn


def _feed(tracker: StateTracker, detector, latencies: list[float]) -> list:
    findings = []
    for i, latency in enumerate(latencies):
        turn = Turn(index=i, request={}, response={"result": "ok"}, latency=latency)
        tracker.record_turn(turn)
        findings.extend(detector.analyze(tracker, turn))
    return findings


def test_latency_drift_detector_silent_on_normal_jitter():
    # baseline window has ordinary jitter; the next turn is a similarly
    # ordinary value, well inside mean + k*stddev.
    tracker = StateTracker()
    detector = LatencyDriftDetector(window=5, k=4.0, floor_seconds=0.05)
    latencies = [0.10, 0.12, 0.09, 0.11, 0.10, 0.12, 0.11]

    findings = _feed(tracker, detector, latencies)

    assert findings == []


def test_latency_drift_detector_fires_on_genuine_spike():
    tracker = StateTracker()
    detector = LatencyDriftDetector(window=5, k=4.0, floor_seconds=0.05)
    # tight baseline (near-zero variance) followed by a spike far beyond any
    # reasonable stddev multiple and well above the absolute floor.
    latencies = [0.01, 0.011, 0.009, 0.010, 0.0105, 0.5]

    findings = _feed(tracker, detector, latencies)

    assert len(findings) == 1
    assert findings[0].detector == "latency_drift"
    assert findings[0].turn_index == 5


def test_latency_drift_detector_ignores_jitter_below_absolute_floor():
    # a fast server with genuinely near-zero latency and near-zero stddev:
    # even a "big" relative jump should not fire if it never clears the
    # absolute floor meant to suppress sub-noise-level flags.
    tracker = StateTracker()
    detector = LatencyDriftDetector(window=5, k=4.0, floor_seconds=0.05)
    latencies = [0.001, 0.0012, 0.0009, 0.0011, 0.0010, 0.002]

    findings = _feed(tracker, detector, latencies)

    assert findings == []


def test_latency_trend_detector_silent_on_flat_latency():
    tracker = StateTracker()
    detector = LatencyTrendDetector(min_turns=8, slope_threshold=0.01, r_squared_threshold=0.5)
    latencies = [0.10, 0.11, 0.09, 0.10, 0.11, 0.10, 0.09, 0.10, 0.11, 0.10]

    findings = _feed(tracker, detector, latencies)

    assert findings == []


# A slow, steady leak: baseline jitter (~0.09-0.12s) followed by a gentle,
# sustained climb where each turn is only ~5ms slower than the last. No
# single turn is an outlier relative to its immediate neighbors or even the
# early baseline's stddev, but the trend across the whole campaign is
# unmistakable. Shared by the two tests below to directly demonstrate the
# gap LatencyTrendDetector fills.
_SLOW_LEAK_LATENCIES = [0.10, 0.12, 0.09, 0.11, 0.10, 0.115, 0.12, 0.125, 0.13, 0.135, 0.14]


def test_latency_trend_detector_fires_on_monotonic_growth_across_whole_history():
    tracker = StateTracker()
    detector = LatencyTrendDetector(min_turns=8, slope_threshold=0.002, r_squared_threshold=0.5)

    findings = _feed(tracker, detector, _SLOW_LEAK_LATENCIES)

    assert findings, "expected the sustained monotonic growth trend to fire"
    assert findings[-1].detector == "latency_trend"
    assert findings[-1].evidence["slope"] > 0.002
    assert findings[-1].evidence["r_squared"] >= 0.5


def test_latency_drift_detector_misses_the_slow_leak_that_trend_detector_catches():
    # documents the gap LatencyTrendDetector fills: the exact same slow,
    # steady growth that fires latency_trend above never clears
    # LatencyDriftDetector's baseline-vs-one-turn threshold, because every
    # turn stays close to its immediate neighbors rather than spiking
    # relative to the early window.
    tracker = StateTracker()
    drift_detector = LatencyDriftDetector(window=5, k=4.0, floor_seconds=0.05)

    findings = _feed(tracker, drift_detector, _SLOW_LEAK_LATENCIES)

    assert findings == []
