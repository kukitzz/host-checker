"""crt.sh Certificate Transparency lookup.

Strictly informational: returns the number of CT log entries for a
domain. Never marks anything as malicious, only as ``UNKNOWN`` with a
useful summary. Useful for spotting newly-registered look-alikes.
"""
from __future__ import annotations

import httpx

from ..core.http import request_with_retry
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider


@register
class CrtShProvider(Provider):
    name = "crtsh"
    supported_types = {IOCType.DOMAIN}
    requires_key = False

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        url = f"https://crt.sh/?q={ioc.value}&output=json"
        resp = await request_with_retry(client, "GET", url, headers={"Accept": "application/json"})
        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                summary=f"crt.sh HTTP {resp.status_code}",
            )
        try:
            data = resp.json()
        except ValueError:
            return ProviderResult(
                provider=self.name, verdict=Verdict.UNKNOWN, summary="invalid JSON"
            )
        count = len(data) if isinstance(data, list) else 0
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.UNKNOWN,  # informational only
            summary=f"{count} certificate transparency entries",
            tags=["ct"] if count else [],
            raw={"count": count},
        )
