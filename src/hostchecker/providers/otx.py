"""AlienVault OTX (Open Threat Exchange) provider.

OTX aggregates community-shared *pulses* — threat reports that
associate an IOC with malware families, campaigns, or actors. Our
heuristic: pulse count > 0 means suspicious, > 3 means malicious.
Tunable from one place if you want a stricter or looser policy.
"""
from __future__ import annotations

from urllib.parse import quote

import httpx

from ..config import settings
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

_BASE = "https://otx.alienvault.com/api/v1/indicators"

_MALICIOUS_PULSE_THRESHOLD = 3


@register
class OTXProvider(Provider):
    name = "otx"
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
        return settings.otx_api_key

    def _endpoint(self, ioc: IOC) -> str:
        if ioc.type == IOCType.IPV4:
            return f"/IPv4/{ioc.value}/general"
        if ioc.type == IOCType.IPV6:
            return f"/IPv6/{ioc.value}/general"
        if ioc.type == IOCType.DOMAIN:
            return f"/domain/{ioc.value}/general"
        if ioc.type == IOCType.URL:
            return f"/url/{quote(ioc.value, safe='')}/general"
        if ioc.type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return f"/file/{ioc.value}/general"
        raise ValueError(f"Unsupported IOC type for OTX: {ioc.type}")

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        headers = {"X-OTX-API-KEY": self.api_key() or ""}
        resp = await client.get(f"{_BASE}{self._endpoint(ioc)}", headers=headers)

        if resp.status_code == 404:
            return ProviderResult(
                provider=self.name, verdict=Verdict.UNKNOWN, summary="Not found in OTX"
            )
        if resp.status_code in (401, 403):
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, summary="Invalid OTX key"
            )
        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                summary=f"OTX HTTP {resp.status_code}",
            )

        data = resp.json()
        pulse_info = data.get("pulse_info") or {}
        pulse_count = int(pulse_info.get("count", 0))

        # Collect malware family / adversary tags from the top pulses.
        tags: set[str] = set()
        for pulse in (pulse_info.get("pulses") or [])[:5]:
            for fam in pulse.get("malware_families") or []:
                if isinstance(fam, dict) and fam.get("display_name"):
                    tags.add(f"malware:{fam['display_name'].lower()}")
            if pulse.get("adversary"):
                tags.add(f"actor:{pulse['adversary'].lower()}")

        if pulse_count >= _MALICIOUS_PULSE_THRESHOLD:
            verdict = Verdict.MALICIOUS
        elif pulse_count > 0:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            summary=f"{pulse_count} OTX pulse(s)",
            tags=sorted(tags),
            raw={"pulse_count": pulse_count},
        )
