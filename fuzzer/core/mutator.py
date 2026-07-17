from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from typing import Any

from .session import StateTracker

_REGISTRY: dict[str, type[MutationPlugin]] = {}
_LOADED = False


class MutationPlugin(ABC):
    """Strategy interface for a single mutation approach. Each turn, the
    engine asks the active plugin to transform the base tool arguments,
    optionally reading/writing campaign-scoped state via ``tracker``."""

    name: str

    @abstractmethod
    def mutate(self, turn_index: int, base_arguments: dict[str, Any], tracker: StateTracker) -> dict[str, Any]:
        """Return the arguments to send for this turn."""


def register(cls: type[MutationPlugin]) -> type[MutationPlugin]:
    _REGISTRY[cls.name] = cls
    return cls


def load_plugins() -> None:
    """Import every module under fuzzer.plugins so that classes decorated
    with @register self-register. Dropping a new file into plugins/ is
    enough to make it available — no other wiring required."""
    global _LOADED
    from .. import plugins as plugins_pkg

    for _, module_name, _ in pkgutil.iter_modules(plugins_pkg.__path__):
        importlib.import_module(f"{plugins_pkg.__name__}.{module_name}")
    _LOADED = True


def get_plugin(name: str) -> MutationPlugin:
    if not _LOADED:
        load_plugins()
    if name not in _REGISTRY:
        raise KeyError(f"unknown mutation plugin '{name}', available: {sorted(_REGISTRY)}")
    return _REGISTRY[name]()


def available_plugins() -> list[str]:
    if not _LOADED:
        load_plugins()
    return sorted(_REGISTRY)
