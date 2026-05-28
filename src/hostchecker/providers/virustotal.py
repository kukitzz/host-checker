"""VirusTotal v3 provider.

Uses the unified `/files`, `/urls`, `/ip_addresses` and `/domains`
endpoints, all of which return ``last_analysis_stats``. We treat any
non-zero ``malicious`` count as malicious, ``suspicious`` > 0 with
zero malicious as suspicious, otherwise clean.
"""
from __future__ import annotations

import base64

import httpx

from ..config import settings
from ..core.http import request_with_retry
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

_BASE = "https://www.virustotal.com/api/v3"


@register
class VirusTotalProvider(Provider):
    name = "virustotal"
    supported_types = {
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }
    requires_key = True

    def api_key(self) -> str | None:
        return settings.virustotal_api_key

    def _endpoint(self, ioc: IOC) -> str:
        if ioc.type in (IOCType.IPV4, IOCType.IPV6):
            return f"/ip_addresses/{ioc.value}"
        if ioc.type == IOCType.DOMAIN:
            return f"/domains/{ioc.value}"
        if ioc.type == IOCType.URL:
            # VT URL IDs are base64url(SHA-less) of the URL, stripped of `=`.
            url_id = base64.urlsafe_b64encode(ioc.value.encode()).rstrip(b"=").decode()
            return f"/urls/{url_id}"
        if ioc.type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return f"/files/{ioc.value}"
        raise ValueError(f"Unsupported IOC type for VirusTotal: {ioc.type}")

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        endpoint = self._endpoint(ioc)
        headers = {"x-apikey": self.api_key() or ""}
        resp = await request_with_retry(client, "GET", f"{_BASE}{endpoint}", headers=headers)

        if resp.status_code == 404:
            return ProviderResult(
                provider=self.name, verdict=Verdict.UNKNOWN, summary="Not found in VirusTotal"
            )
        if resp.status_code == 401:
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, summary="Invalid VirusTotal API key"
            )
        if resp.status_code == 429:
            return ProviderResult(
                provider=self.name, verdict=Verdict.RATE_LIMITED, summary="VirusTotal rate limited"
            )
        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                summary=f"VirusTotal HTTP {resp.status_code}",
            )

        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        engines = malicious + suspicious + harmless + undetected

        if malicious > 0:
            verdict = Verdict.MALICIOUS
        elif suspicious > 0:
            verdict = Verdict.SUSPICIOUS
        elif engines > 0:
            verdict = Verdict.CLEAN
        else:
            verdict = Verdict.UNKNOWN

        summary = (
            f"{malicious}/{engines} engines flag malicious, {suspicious} suspicious"
            if engines
            else "No engine results"
        )
        tags = sorted({t for t in (data.get("tags") or []) if isinstance(t, str)})
        score = (malicious + 0.5 * suspicious) / engines if engines else None

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            score=score,
            summary=summary,
            tags=tags,
            raw={"last_analysis_stats": stats},
        )
