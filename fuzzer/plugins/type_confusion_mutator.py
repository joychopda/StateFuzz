from __future__ import annotations

from typing import Any

from ..core.mutator import MutationPlugin, register
from ..core.session import StateTracker

_STRATEGIES = ("swap_types", "drop_key", "inject_null", "oversized_string", "deep_nesting")
_OVERSIZED_STRING_LENGTH = 100_000
_NESTING_DEPTH = 200


@register
class TypeConfusionMutator(MutationPlugin):
    """Boundary/type-confusion plugin: rotates through schema-violating
    transformations of one argument per turn to probe how strictly the
    server validates tool call inputs. Handlers that skip validation and
    just trust the declared schema tend to crash (unhandled TypeError/
    KeyError) or silently misbehave instead of cleanly rejecting the call —
    both are real bugs, not just noise."""

    name = "type_confusion"

    def mutate(self, turn_index: int, base_arguments: dict[str, Any], tracker: StateTracker) -> dict[str, Any]:
        mutated = dict(base_arguments)
        keys = list(base_arguments.keys())
        if not keys:
            return mutated

        strategy = _STRATEGIES[turn_index % len(_STRATEGIES)]
        target_key = keys[turn_index % len(keys)]

        if strategy == "swap_types":
            mutated[target_key] = self._swapped_type(base_arguments[target_key])
        elif strategy == "drop_key":
            del mutated[target_key]
        elif strategy == "inject_null":
            mutated[target_key] = None
        elif strategy == "oversized_string":
            mutated[target_key] = "A" * _OVERSIZED_STRING_LENGTH
        elif strategy == "deep_nesting":
            mutated[target_key] = self._deeply_nested(_NESTING_DEPTH)

        tracker.state.custom.setdefault("type_confusion:strategy_log", []).append(
            {"turn": turn_index, "strategy": strategy, "key": target_key}
        )
        return mutated

    @staticmethod
    def _swapped_type(value: Any) -> Any:
        if isinstance(value, bool):
            return not value
        if isinstance(value, str):
            return 1337
        if isinstance(value, int):
            return str(value)
        return "1337"

    @staticmethod
    def _deeply_nested(depth: int) -> Any:
        node: Any = "bottom"
        for _ in range(depth):
            node = {"nested": node}
        return node
