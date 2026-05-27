"""Provider discovery and instantiation.

A *registry* keeps the list of all known provider classes. Providers
self-register at import time via :func:`register`. The orchestrator asks
the registry which providers are enabled (have credentials or are
keyless) and which support a given IOC type.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..providers.base import Provider


_REGISTRY: list[type[Provider]] = []


def register(cls: type[Provider]) -> type[Provider]:
    """Decorator: add a provider class to the global registry."""
    _REGISTRY.append(cls)
    return cls


def all_provider_classes() -> list[type[Provider]]:
    return list(_REGISTRY)


def enabled_providers() -> list[Provider]:
    """Instantiate every provider that has the credentials it needs."""
    instances: list[Provider] = []
    for cls in _REGISTRY:
        instance = cls()
        if instance.is_enabled():
            instances.append(instance)
    return instances
