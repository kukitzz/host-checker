"""IPinfo provider — IP geolocation, ASN and (with the paid privacy
add-on) VPN / proxy detection.

Works **keyless** with a generous anonymous rate limit; passing
``HC_IPINFO_API_KEY`` raises that limit to 50k/month and unlocks the
account-specific add-ons you've subscribed to.

This is enrichment, not a verdict — we never mark an IP as malicious
based on its geolocation. The result is mostly tags so the rest of
your tooling can pivot on country / ASN / hosting tier.
"""
from __future__ import annotations

import httpx

from ..config import settings
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

_URL = "https://ipinfo.io/{ip}/json"

# Substring hints in the `org` field that suggest hosting / VPN / proxy.
# Purely heuristic — IPinfo's actual privacy data lives behind the paid add-on.
_HOSTING_HINTS = ("hosting", "datacenter", "cloud", "vpn", "proxy", "ovh", "aws", "amazon")


@register
class IPinfoProvider(Provider):
    name = "ipinfo"
    supported_types = {IOCType.IPV4, IOCType.IPV6}
    requires_key = False  # keyless works; key only bumps limits

    def api_key(self) -> str | None:
        return settings.ipinfo_api_key

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        headers = {"Accept": "application/json"}
        if key := self.api_key():
            headers["Authorization"] = f"Bearer {key}"
        resp = await client.get(_URL.format(ip=ioc.value), headers=headers)

        if resp.status_code == 429:
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, summary="IPinfo rate limited"
            )
        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                summary=f"IPinfo HTTP {resp.status_code}",
            )

        data = resp.json()
        country = data.get("country")
        city = data.get("city")
        org = data.get("org")
        hostname = data.get("hostname")
        # The paid privacy add-on returns these keys; absent on free tier.
        privacy = data.get("privacy") or {}
        is_vpn = bool(privacy.get("vpn"))
        is_proxy = bool(privacy.get("proxy"))
        is_tor = bool(privacy.get("tor"))
        is_hosting = bool(privacy.get("hosting"))

        tags: list[str] = []
        if country:
            tags.append(f"country:{country}")
        if org:
            tags.append(f"org:{org}")
            org_lc = org.lower()
            if any(hint in org_lc for hint in _HOSTING_HINTS):
                tags.append("hosting_hint")
        for flag, name in (
            (is_vpn, "vpn"),
            (is_proxy, "proxy"),
            (is_tor, "tor"),
            (is_hosting, "hosting"),
        ):
            if flag:
                tags.append(name)

        # Authoritative privacy hits → SUSPICIOUS. Heuristic-only stays UNKNOWN.
        verdict = (
            Verdict.SUSPICIOUS if (is_vpn or is_proxy or is_tor) else Verdict.UNKNOWN
        )

        pieces = [p for p in (country, city, org, f"PTR: {hostname}" if hostname else None) if p]
        summary = "IPinfo: " + " • ".join(pieces) if pieces else "IPinfo: no data"

        return ProviderResult(
            provider=self.name, verdict=verdict, summary=summary, tags=tags, raw=data
        )
