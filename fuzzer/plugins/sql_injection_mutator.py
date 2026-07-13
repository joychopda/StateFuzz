from __future__ import annotations

from typing import Any

from ..core.mutator import MutationPlugin, register
from ..core.session import StateTracker

_PAYLOAD_TEMPLATES = [
    "' OR '1'='1",
    "'; DROP TABLE sessions--",
    "' UNION SELECT session_id, NULL--",
    '" OR "1"="1',
    "' AND SLEEP(0)--",
]


@register
class SQLInjectionMutator(MutationPlugin):
    """Appends SQLi-style payloads to every string argument. Each turn is
    also tagged with a unique marker recorded on the tracker, so detectors
    like CrossTurnLeakDetector can tell whether a later turn's response
    surfaces data derived from an earlier, differently-keyed call."""

    name = "sql_injection"

    def mutate(self, turn_index: int, base_arguments: dict[str, Any], tracker: StateTracker) -> dict[str, Any]:
        marker = f"SFUZZ-{tracker.state.session_id or 'nosession'}-{turn_index}"
        tracker.add_marker(marker)

        payload = _PAYLOAD_TEMPLATES[turn_index % len(_PAYLOAD_TEMPLATES)]
        mutated = dict(base_arguments)
        for key, value in base_arguments.items():
            if isinstance(value, str):
                mutated[key] = f"{value}-{marker}{payload}"
        return mutated
