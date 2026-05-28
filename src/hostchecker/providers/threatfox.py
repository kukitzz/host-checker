"""abuse.ch ThreatFox provider.

ThreatFox is abuse.ch's database of malware IOCs (IPs, domains, URLs,
hashes) tied to specific malware families and threat types. Any
positive match here is treated as malicious — ThreatFox doesn't list
benign infrastructure.
"""
from __future__ import annotations

import httpx

from ..config import settings
from ..core.http import request_with_retry
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

_URL = "https://threatfox-api.abuse.ch/api/v1/"


@register
class ThreatFoxProvider(Provider):
    name = "threatfox"
    supported_types = {
        IOCType.IPV4,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }
    requires_key = True  # abuse.ch moved to mandatory free Auth-Key

    def api_key(self) -> str | None:
        return settings.abusech_auth_key

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        headers = {"Auth-Key": self.api_key() or "", "Accept": "application/json"}
        body = {"query": "search_ioc", "search_term": ioc.value}
        resp = await request_with_retry(client, "POST", _URL, headers=headers, json=body)

        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                summary=f"ThreatFox HTTP {resp.status_code}",
            )

        try:
            payload = resp.json()
        except ValueError:
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, summary="ThreatFox invalid JSON"
            )

        status = payload.get("query_status")
        if status == "no_result":
            return ProviderResult(
                provider=self.name, verdict=Verdict.CLEAN, summary="Not listed on ThreatFox"
            )
        if status != "ok":
            return ProviderResult(
                provider=self.name, verdict=Verdict.UNKNOWN, summary=f"status={status}"
            )

        hits = payload.get("data") or []
        tags: set[str] = set()
        threat_types: set[str] = set()
        for hit in hits[:5]:
            if mal := hit.get("malware_printable"):
                tags.add(f"malware:{str(mal).lower()}")
            if tt := hit.get("threat_type"):
                threat_types.add(str(tt))
            for t in hit.get("tags") or []:
                tags.add(str(t).lower())

        return ProviderResult(
            provider=self.name,
            verdict=Verdict.MALICIOUS,
            summary=f"{len(hits)} ThreatFox hit(s)"
            + (f" • {', '.join(sorted(threat_types))}" if threat_types else ""),
            tags=sorted(tags),
            raw={"hit_count": len(hits)},
        )
