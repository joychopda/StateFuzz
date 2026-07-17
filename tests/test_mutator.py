import pytest

from fuzzer.core.mutator import available_plugins, get_plugin


def test_available_plugins_includes_all_bundled_plugins():
    names = available_plugins()

    assert names == sorted(names), "available_plugins() must return a sorted list"
    for expected in ("sql_injection", "type_confusion", "identity_confusion"):
        assert expected in names


def test_get_plugin_returns_a_fresh_instance_each_time():
    first = get_plugin("sql_injection")
    second = get_plugin("sql_injection")

    assert first is not second
    assert first.name == second.name == "sql_injection"


def test_get_plugin_raises_key_error_for_unknown_name():
    with pytest.raises(KeyError, match="unknown mutation plugin"):
        get_plugin("does_not_exist")
