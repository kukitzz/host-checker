"""Shodan provider — IP service inventory and known CVEs.

Shodan doesn't return a malicious/clean verdict — it returns what's
*running* on the host. We translate that into:

* ``SUSPICIOUS`` if any ``vulns`` (CVE IDs) are reported. Known
  vulnerabilities aren't the same as malice but warrant a closer look.
* ``UNKNOWN`` otherwise, with rich ports / org / country tags so the
  user can pivot the investigation from there.
"""
from __future__ import annotations

import httpx

from ..config import settings
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

_URL = "https://api.shodan.io/shodan/host/{ip}"


@register
class ShodanProvider(Provider):
    name = "shodan"
    supported_types = {IOCType.IPV4, IOCType.IPV6}
    requires_key = True

    def api_key(self) -> str | None:
        return settings.shodan_api_key

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        resp = await client.get(
            _URL.format(ip=ioc.value),
            params={"key": self.api_key() or ""},
        )

        if resp.status_code == 404:
            return ProviderResult(
                provider=self.name, verdict=Verdict.UNKNOWN, summary="Not in Shodan"
            )
        if resp.status_code in (401, 403):
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, summary="Invalid Shodan key"
            )
        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                summary=f"Shodan HTTP {resp.status_code}",
            )

        data = resp.json()
        ports = data.get("ports") or []
        vulns = list(data.get("vulns") or [])
        org = data.get("org")
        country = data.get("country_code")
        shodan_tags = data.get("tags") or []

        verdict = Verdict.SUSPICIOUS if vulns else Verdict.UNKNOWN

        tags: list[str] = []
        tags.extend(f"port:{p}" for p in sorted(ports)[:8])
        tags.extend(f"cve:{c}" for c in vulns[:8])
        tags.extend(str(t).lower() for t in shodan_tags)
        if country:
            tags.append(f"country:{country}")

        pieces: list[str] = []
        if ports:
            pieces.append(f"{len(ports)} open port(s)")
        if vulns:
            pieces.append(f"{len(vulns)} CVE(s)")
        if org:
            pieces.append(org)
        if country:
            pieces.append(country)
        summary = "Shodan: " + " • ".join(pieces) if pieces else "Shodan: indexed, no detail"

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            summary=summary,
            tags=tags,
            raw={"ports": ports, "vulns": vulns, "org": org, "country": country},
        )
