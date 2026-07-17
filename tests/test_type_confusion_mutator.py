from fuzzer.core.session import StateTracker
from fuzzer.plugins.type_confusion_mutator import TypeConfusionMutator


def test_mutate_returns_copy_not_the_original_dict():
    tracker = StateTracker()
    plugin = TypeConfusionMutator()
    base = {"age": 30}

    mutated = plugin.mutate(0, base, tracker)

    assert mutated is not base
    assert base == {"age": 30}, "base_arguments must not be mutated in place"


def test_mutate_on_empty_arguments_is_a_noop():
    tracker = StateTracker()
    plugin = TypeConfusionMutator()

    mutated = plugin.mutate(0, {}, tracker)

    assert mutated == {}


def test_swap_types_strategy_changes_the_value_type():
    tracker = StateTracker()
    plugin = TypeConfusionMutator()
    base = {"age": 30}

    mutated = plugin.mutate(0, base, tracker)  # turn 0 % 5 == "swap_types"

    assert isinstance(mutated["age"], str)
    assert not isinstance(mutated["age"], bool)


def test_drop_key_strategy_removes_the_key():
    tracker = StateTracker()
    plugin = TypeConfusionMutator()
    base = {"age": 30}

    mutated = plugin.mutate(1, base, tracker)  # turn 1 % 5 == "drop_key"

    assert "age" not in mutated


def test_inject_null_strategy_sets_value_to_none():
    tracker = StateTracker()
    plugin = TypeConfusionMutator()
    base = {"age": 30}

    mutated = plugin.mutate(2, base, tracker)  # turn 2 % 5 == "inject_null"

    assert mutated["age"] is None


def test_oversized_string_strategy_produces_a_huge_string():
    tracker = StateTracker()
    plugin = TypeConfusionMutator()
    base = {"age": 30}

    mutated = plugin.mutate(3, base, tracker)  # turn 3 % 5 == "oversized_string"

    assert isinstance(mutated["age"], str)
    assert len(mutated["age"]) >= 100_000


def test_deep_nesting_strategy_produces_a_deeply_nested_object():
    tracker = StateTracker()
    plugin = TypeConfusionMutator()
    base = {"age": 30}

    mutated = plugin.mutate(4, base, tracker)  # turn 4 % 5 == "deep_nesting"

    depth = 0
    node = mutated["age"]
    while isinstance(node, dict):
        node = node["nested"]
        depth += 1
    assert depth >= 100
    assert node == "bottom"


def test_strategy_log_is_recorded_on_the_tracker():
    tracker = StateTracker()
    plugin = TypeConfusionMutator()
    base = {"age": 30}

    plugin.mutate(0, base, tracker)
    plugin.mutate(1, base, tracker)

    log = tracker.state.custom["type_confusion:strategy_log"]
    assert [entry["strategy"] for entry in log] == ["swap_types", "drop_key"]
    assert all(entry["key"] == "age" for entry in log)
