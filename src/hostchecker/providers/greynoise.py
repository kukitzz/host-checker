"""GreyNoise community API — IP-only context.

GreyNoise classifies internet-wide scanners: a ``benign`` classification
on an IP that AbuseIPDB flags as malicious typically means a known
scanner, useful for reducing false positives.
"""
from __future__ import annotations

import httpx

from ..config import settings
from ..core.http import request_with_retry
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

_URL = "https://api.greynoise.io/v3/community/{ip}"


@register
class GreyNoiseProvider(Provider):
    name = "greynoise"
    supported_types = {IOCType.IPV4}
    requires_key = True

    def api_key(self) -> str | None:
        return settings.greynoise_api_key

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        headers = {"Accept": "application/json", "key": self.api_key() or ""}
        resp = await request_with_retry(client, "GET", _URL.format(ip=ioc.value), headers=headers)

        if resp.status_code == 404:
            return ProviderResult(
                provider=self.name, verdict=Verdict.UNKNOWN, summary="Not observed by GreyNoise"
            )
        if resp.status_code == 401:
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, summary="Invalid GreyNoise key"
            )
        if resp.status_code == 429:
            return ProviderResult(
                provider=self.name, verdict=Verdict.RATE_LIMITED, summary="GreyNoise rate limited"
            )
        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                summary=f"GreyNoise HTTP {resp.status_code}",
            )

        data = resp.json()
        classification = data.get("classification", "unknown")  # benign | malicious | unknown
        name = data.get("name") or ""
        noise = bool(data.get("noise"))
        riot = bool(data.get("riot"))

        verdict_map = {
            "benign": Verdict.CLEAN,
            "malicious": Verdict.MALICIOUS,
            "unknown": Verdict.SUSPICIOUS if noise else Verdict.UNKNOWN,
        }
        verdict = verdict_map.get(classification, Verdict.UNKNOWN)
        tags = []
        if noise:
            tags.append("noise")
        if riot:
            tags.append("riot")
        if name:
            tags.append(f"actor:{name}")

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            summary=f"GreyNoise: {classification}{f' ({name})' if name else ''}",
            tags=tags,
            raw=data,
        )
