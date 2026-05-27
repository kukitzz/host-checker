"""Abstract base for all threat-intel providers.

Subclasses must declare :attr:`name` and :attr:`supported_types`, set
:attr:`requires_key` correctly, and implement :meth:`query`. They should
*not* maintain their own HTTP client — one is passed in.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

import httpx

from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult


class Provider(ABC):
    name: ClassVar[str] = ""
    supported_types: ClassVar[set[IOCType]] = set()
    requires_key: ClassVar[bool] = False

    # ----- enablement ------------------------------------------------------

    def is_enabled(self) -> bool:
        """Whether this provider has everything it needs to run.

        Default: enabled if no key is required, otherwise enabled only if
        :meth:`api_key` returns something truthy. Override for more
        complex requirements (e.g. two keys).
        """
        if not self.requires_key:
            return True
        return bool(self.api_key())

    def api_key(self) -> str | None:  # noqa: D401 — small helper
        """Return the API key for this provider, if any."""
        return None

    # ----- query -----------------------------------------------------------

    @abstractmethod
    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        """Query the provider for a single IOC and return a normalised result."""
        raise NotImplementedError
