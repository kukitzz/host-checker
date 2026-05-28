"""URLhaus (abuse.ch) — malicious URL / payload database.

Supports two modes:

* **Keyless**: queries the public read-only API endpoints that don't
  require an Auth-Key. We use the ``payload`` lookup for hashes and the
  ``host`` lookup for IPs/domains.
* **With ``HC_ABUSECH_AUTH_KEY``**: identical endpoints but authenticated,
  yielding higher rate limits and consistent uptime.

URLhaus's per-IOC endpoints have been keyless historically; abuse.ch
moved most APIs behind a free Auth-Key in 2024. The code below sends
the header when a key is configured and otherwise falls back to a plain
request, so it degrades gracefully.
"""
from __future__ import annotations

import httpx

from ..config import settings
from ..core.http import request_with_retry
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

_BASE = "https://urlhaus-api.abuse.ch/v1"


@register
class URLhausProvider(Provider):
    name = "urlhaus"
    supported_types = {IOCType.IPV4, IOCType.DOMAIN, IOCType.URL, IOCType.MD5, IOCType.SHA256}
    requires_key = False  # works keyless; key only improves limits

    def api_key(self) -> str | None:
        return settings.abusech_auth_key

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {}
        if key := self.api_key():
            h["Auth-Key"] = key
        return h

    async def _post(
        self, client: httpx.AsyncClient, path: str, data: dict[str, str]
    ) -> dict | None:
        resp = await request_with_retry(
            client, "POST", f"{_BASE}/{path}/", data=data, headers=self._headers()
        )
        if resp.status_code != 200:
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        if ioc.type in (IOCType.IPV4, IOCType.DOMAIN):
            payload = await self._post(client, "host", {"host": ioc.value})
        elif ioc.type == IOCType.URL:
            payload = await self._post(client, "url", {"url": ioc.value})
        elif ioc.type in (IOCType.MD5, IOCType.SHA256):
            field = "md5_hash" if ioc.type == IOCType.MD5 else "sha256_hash"
            payload = await self._post(client, "payload", {field: ioc.value})
        else:
            return ProviderResult(provider=self.name, verdict=Verdict.SKIPPED)

        if not payload:
            return ProviderResult(
                provider=self.name, verdict=Verdict.UNKNOWN, summary="No response"
            )

        status = payload.get("query_status")
        if status in ("no_results", "not_listed"):
            return ProviderResult(
                provider=self.name, verdict=Verdict.CLEAN, summary="Not listed on URLhaus"
            )
        if status != "ok":
            return ProviderResult(
                provider=self.name, verdict=Verdict.UNKNOWN, summary=f"status={status}"
            )

        urls = payload.get("urls") or []
        online_count = sum(1 for u in urls if u.get("url_status") == "online")
        tags: list[str] = []
        for u in urls[:5]:
            tags.extend(u.get("tags") or [])
        tags = sorted({t for t in tags if t})

        verdict = Verdict.MALICIOUS if (urls or payload.get("url_status") == "online") \
            else Verdict.SUSPICIOUS

        summary = (
            f"{len(urls)} malicious URL(s) on URLhaus, {online_count} online"
            if urls
            else "Listed on URLhaus"
        )
        return ProviderResult(
            provider=self.name, verdict=verdict, summary=summary, tags=tags, raw=payload
        )
