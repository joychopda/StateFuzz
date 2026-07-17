from __future__ import annotations

from typing import Any

from ..core.mutator import MutationPlugin, register
from ..core.session import StateTracker

_ID_KEY_HINTS = ("id", "session", "user", "token", "key", "account", "role")
_PRIVILEGED_SENTINELS = ["admin", "root", "0", "system"]


@register
class IdentityConfusionMutator(MutationPlugin):
    """Session/identity-confusion plugin: finds the argument that looks like
    a session/user/account identifier and mutates it turn over turn to probe
    whether authorization is actually re-derived from that identity on every
    call, or whether a grant/decision made for one identity keeps applying
    after the identity changes — the class of bug the README calls out as
    "authorization state drifts after a specific sequence of calls".

    Turn 0 replays the identity unmodified (a legitimate baseline call).
    Later turns rotate through: a completely different identity, a "neighbor"
    identity (enumeration), and a privileged-looking sentinel value, then
    cycle back — so a detector or a human reading the report can directly
    compare what each identity was allowed to do."""

    name = "identity_confusion"

    def mutate(self, turn_index: int, base_arguments: dict[str, Any], tracker: StateTracker) -> dict[str, Any]:
        mutated = dict(base_arguments)
        id_key = self._find_identity_key(base_arguments)
        if id_key is None:
            return mutated

        original_value = base_arguments[id_key]
        strategy = turn_index % 4
        if strategy == 0:
            new_value = original_value
        elif strategy == 1:
            new_value = self._different_identity(original_value)
        elif strategy == 2:
            new_value = self._neighbor_identity(original_value)
        else:
            new_value = _PRIVILEGED_SENTINELS[turn_index % len(_PRIVILEGED_SENTINELS)]

        mutated[id_key] = new_value
        tracker.state.custom.setdefault("identity_confusion:mutations", []).append(
            {"turn": turn_index, "key": id_key, "original": original_value, "mutated": new_value}
        )
        return mutated

    @staticmethod
    def _find_identity_key(arguments: dict[str, Any]) -> str | None:
        for key in arguments:
            lowered = key.lower()
            if any(hint in lowered for hint in _ID_KEY_HINTS):
                return key
        return None

    @staticmethod
    def _different_identity(value: Any) -> Any:
        if isinstance(value, int):
            return value + 9999
        return f"{value}-other"

    @staticmethod
    def _neighbor_identity(value: Any) -> Any:
        if isinstance(value, int):
            return value - 1 if value > 0 else value + 1
        return f"{value}0"
