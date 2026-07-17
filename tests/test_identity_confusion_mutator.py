from fuzzer.core.session import StateTracker
from fuzzer.plugins.identity_confusion_mutator import IdentityConfusionMutator


def test_mutate_returns_copy_not_the_original_dict():
    tracker = StateTracker()
    plugin = IdentityConfusionMutator()
    base = {"user_id": "alice", "role": "admin"}

    mutated = plugin.mutate(0, base, tracker)

    assert mutated is not base
    assert base == {"user_id": "alice", "role": "admin"}


def test_turn_zero_replays_the_original_identity_unmodified():
    tracker = StateTracker()
    plugin = IdentityConfusionMutator()
    base = {"user_id": "alice", "role": "admin"}

    mutated = plugin.mutate(0, base, tracker)

    assert mutated["user_id"] == "alice"


def test_strategy_one_swaps_to_a_completely_different_identity():
    tracker = StateTracker()
    plugin = IdentityConfusionMutator()
    base = {"user_id": "alice", "role": "admin"}

    mutated = plugin.mutate(1, base, tracker)

    assert mutated["user_id"] != "alice"


def test_strategy_two_produces_a_neighbor_identity():
    tracker = StateTracker()
    plugin = IdentityConfusionMutator()
    base = {"user_id": 42}

    mutated = plugin.mutate(2, base, tracker)

    assert mutated["user_id"] != 42
    assert mutated["user_id"] == 41


def test_strategy_three_injects_a_privileged_sentinel():
    tracker = StateTracker()
    plugin = IdentityConfusionMutator()
    base = {"user_id": "alice"}

    mutated = plugin.mutate(3, base, tracker)

    assert mutated["user_id"] in ("admin", "root", "0", "system")


def test_no_identity_like_key_is_a_noop():
    tracker = StateTracker()
    plugin = IdentityConfusionMutator()
    base = {"value": "trusted-default"}

    mutated = plugin.mutate(1, base, tracker)

    assert mutated == base


def test_mutation_log_is_recorded_on_the_tracker():
    tracker = StateTracker()
    plugin = IdentityConfusionMutator()
    base = {"user_id": "alice"}

    plugin.mutate(0, base, tracker)
    plugin.mutate(1, base, tracker)

    log = tracker.state.custom["identity_confusion:mutations"]
    assert len(log) == 2
    assert log[0]["original"] == "alice"
    assert log[0]["mutated"] == "alice"
    assert log[1]["mutated"] != "alice"
