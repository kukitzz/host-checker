"""SecurityTrails provider — passive DNS / historical infrastructure.

For a **domain**, we pull the historical A-record set: how many distinct
IPs the domain has resolved to over time. A domain that has rotated
through many IPs in a short window is a fast-flux / bulletproof-hosting
signal worth flagging — but SecurityTrails reports facts, not verdicts,
so we stay conservative: lots of historical IPs → ``SUSPICIOUS``, else
``UNKNOWN`` with the count surfaced as enrichment.

For an **IP**, we pull the reverse: how many domains currently point at
it (shared-hosting density), surfaced as a tag.

Requires a free API key from https://securitytrails.com/ (50 queries/mo
on the free tier).
"""
from __future__ import annotations

import httpx

from ..config import settings
from ..core.http import request_with_retry
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

_HISTORY_URL = "https://api.securitytrails.com/v1/history/{domain}/dns/a"
_IP_NEIGHBOURS_URL = "https://api.securitytrails.com/v1/ips/nearby/{ip}"

# A domain that has used more than this many distinct IPs historically is
# flagged as suspicious (fast-flux-like behaviour).
_FASTFLUX_IP_THRESHOLD = 10


@register
class SecurityTrailsProvider(Provider):
    name = "securitytrails"
    supported_types = {IOCType.DOMAIN, IOCType.IPV4}
    requires_key = True

    def api_key(self) -> str | None:
        return settings.securitytrails_api_key

    def _headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "APIKEY": self.api_key() or ""}

    async def _query_domain(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        resp = await request_with_retry(
            client, "GET", _HISTORY_URL.format(domain=ioc.value), headers=self._headers()
        )
        if resp.status_code == 401:
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, summary="Invalid SecurityTrails key"
            )
        if resp.status_code == 429:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.RATE_LIMITED,
                summary="SecurityTrails rate limited",
            )
        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                summary=f"SecurityTrails HTTP {resp.status_code}",
            )

        data = resp.json()
        records = data.get("records") or []
        # Each record has "values": [{"ip": "...", ...}]. Collect distinct IPs.
        distinct_ips: set[str] = set()
        for rec in records:
            for v in rec.get("values") or []:
                if ip := v.get("ip"):
                    distinct_ips.add(ip)

        count = len(distinct_ips)
        verdict = Verdict.SUSPICIOUS if count > _FASTFLUX_IP_THRESHOLD else Verdict.UNKNOWN
        tags = [f"historical_ips:{count}"]
        if count > _FASTFLUX_IP_THRESHOLD:
            tags.append("fast-flux-suspect")

        summary = (
            f"SecurityTrails: {count} distinct historical IP(s) "
            f"across {len(records)} record(s)"
        )
        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            summary=summary,
            tags=tags,
            raw={"distinct_ip_count": count, "record_count": len(records)},
        )

    async def _query_ip(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        resp = await request_with_retry(
            client, "GET", _IP_NEIGHBOURS_URL.format(ip=ioc.value), headers=self._headers()
        )
        if resp.status_code == 401:
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, summary="Invalid SecurityTrails key"
            )
        if resp.status_code == 429:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.RATE_LIMITED,
                summary="SecurityTrails rate limited",
            )
        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                summary=f"SecurityTrails HTTP {resp.status_code}",
            )

        data = resp.json()
        blocks = data.get("blocks") or []
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.UNKNOWN,
            summary=f"SecurityTrails: {len(blocks)} nearby IP block(s)",
            tags=[f"nearby_blocks:{len(blocks)}"],
            raw={"block_count": len(blocks)},
        )

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        if ioc.type == IOCType.DOMAIN:
            return await self._query_domain(ioc, client)
        return await self._query_ip(ioc, client)
