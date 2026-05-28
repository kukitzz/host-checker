"""Tor Project bulk exit-list provider.

Downloads the canonical exit list once per process and caches it
in-memory. Marks IPs as SUSPICIOUS (not malicious) because being a Tor
exit is legal and common in legitimate traffic.
"""
from __future__ import annotations

import asyncio

import httpx

from ..core.http import request_with_retry
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

_LIST_URL = "https://check.torproject.org/torbulkexitlist"


@register
class TorExitProvider(Provider):
    name = "tor_exit"
    supported_types = {IOCType.IPV4, IOCType.IPV6}
    requires_key = False

    _cache: set[str] | None = None
    _lock: asyncio.Lock = asyncio.Lock()

    async def _load(self, client: httpx.AsyncClient) -> set[str]:
        if TorExitProvider._cache is not None:
            return TorExitProvider._cache
        async with TorExitProvider._lock:
            if TorExitProvider._cache is None:
                resp = await request_with_retry(client, "GET", _LIST_URL)
                resp.raise_for_status()
                TorExitProvider._cache = {
                    line.strip() for line in resp.text.splitlines() if line.strip()
                }
        return TorExitProvider._cache

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        exit_set = await self._load(client)
        is_exit = ioc.value in exit_set
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.SUSPICIOUS if is_exit else Verdict.CLEAN,
            summary="Listed as Tor exit node" if is_exit else "Not a Tor exit node",
            tags=["tor"] if is_exit else [],
        )
