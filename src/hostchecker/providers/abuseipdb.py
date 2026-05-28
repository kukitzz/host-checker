"""AbuseIPDB v2 ``/check`` provider — IP reputation only."""
from __future__ import annotations

import httpx

from ..config import settings
from ..core.http import request_with_retry
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

_URL = "https://api.abuseipdb.com/api/v2/check"


@register
class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    supported_types = {IOCType.IPV4, IOCType.IPV6}
    requires_key = True

    def api_key(self) -> str | None:
        return settings.abuseipdb_api_key

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        headers = {"Accept": "application/json", "Key": self.api_key() or ""}
        params = {"ipAddress": ioc.value, "maxAgeInDays": "90", "verbose": ""}
        resp = await request_with_retry(client, "GET", _URL, headers=headers, params=params)

        if resp.status_code == 401:
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, summary="Invalid AbuseIPDB key"
            )
        if resp.status_code == 429:
            return ProviderResult(
                provider=self.name, verdict=Verdict.RATE_LIMITED, summary="AbuseIPDB rate limited"
            )
        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                summary=f"AbuseIPDB HTTP {resp.status_code}",
            )

        data = resp.json().get("data", {})
        confidence = int(data.get("abuseConfidenceScore", 0))
        total_reports = int(data.get("totalReports", 0))
        country = data.get("countryCode")
        isp = data.get("isp")

        if confidence >= 75:
            verdict = Verdict.MALICIOUS
        elif confidence >= 25:
            verdict = Verdict.SUSPICIOUS
        elif total_reports == 0:
            verdict = Verdict.CLEAN
        else:
            verdict = Verdict.SUSPICIOUS

        tags = []
        if data.get("isTor"):
            tags.append("tor")
        if data.get("usageType"):
            tags.append(str(data["usageType"]).lower().replace(" ", "_"))

        summary = (
            f"AbuseIPDB confidence {confidence}%, {total_reports} reports"
            f"{f' • {country}' if country else ''}"
            f"{f' • {isp}' if isp else ''}"
        )

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            score=confidence / 100,
            summary=summary,
            tags=tags,
            raw=data,
        )
