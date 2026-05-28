"""RDAP provider — registration data for domains and IPs.

RDAP (RFC 7482/9082/9083) is the IANA-mandated successor to WHOIS. It's
keyless, returns structured JSON, and the bootstrap registry routes a
query to the authoritative server automatically — so a single endpoint,
``https://rdap.org/``, transparently redirects to the right registry.

What we extract:

* **Domains** — registration ("registration"/"creation") date. A domain
  registered very recently is a classic phishing / C2 signal, so we map
  age < 30 days to ``SUSPICIOUS``. Older domains are ``UNKNOWN`` (RDAP
  doesn't carry reputation, only facts). Registrar and status are
  surfaced as tags.
* **IPs** — the assigned network: name, country, and the responsible
  organisation. Always ``UNKNOWN`` — purely enrichment.
"""
from __future__ import annotations

from datetime import UTC, datetime

import httpx

from ..core.http import request_with_retry
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

# rdap.org is a redirector that follows the IANA RDAP bootstrap registry.
_DOMAIN_URL = "https://rdap.org/domain/{value}"
_IP_URL = "https://rdap.org/ip/{value}"

# Domains younger than this are flagged suspicious.
_NEW_DOMAIN_DAYS = 30


def _parse_rdap_date(value: str) -> datetime | None:
    """Parse an RDAP eventDate (ISO 8601, usually with timezone)."""
    try:
        # Python 3.11+ fromisoformat handles the trailing 'Z'.
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _first_event_date(events: list[dict], *actions: str) -> datetime | None:
    """Return the first eventDate matching any of ``actions``."""
    for action in actions:
        for ev in events:
            if ev.get("eventAction") == action and ev.get("eventDate"):
                dt = _parse_rdap_date(ev["eventDate"])
                if dt:
                    return dt
    return None


def _registrar_name(entities: list[dict]) -> str | None:
    """Dig the registrar's name out of the (deeply nested) entities array."""
    for ent in entities:
        roles = ent.get("roles") or []
        if "registrar" not in roles:
            continue
        # vcardArray: ["vcard", [ ["version",...], ["fn", {}, "text", "Name"], ... ]]
        vcard = ent.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2:
            for entry in vcard[1]:
                if isinstance(entry, list) and entry and entry[0] == "fn":
                    return str(entry[3]) if len(entry) > 3 else None
    return None


@register
class RDAPProvider(Provider):
    name = "rdap"
    supported_types = {IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6}
    requires_key = False

    async def _query_domain(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        resp = await request_with_retry(
            client, "GET", _DOMAIN_URL.format(value=ioc.value),
            headers={"Accept": "application/rdap+json"},
        )
        if resp.status_code == 404:
            return ProviderResult(
                provider=self.name, verdict=Verdict.UNKNOWN, summary="No RDAP record"
            )
        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, summary=f"RDAP HTTP {resp.status_code}"
            )

        data = resp.json()
        events = data.get("events") or []
        entities = data.get("entities") or []
        statuses = data.get("status") or []

        registered = _first_event_date(events, "registration", "creation")
        registrar = _registrar_name(entities)

        tags: list[str] = []
        if registrar:
            tags.append(f"registrar:{registrar.lower()}")
        for s in statuses[:5]:
            tags.append(f"status:{str(s).replace(' ', '_')}")

        verdict = Verdict.UNKNOWN
        age_str = "unknown age"
        if registered:
            age_days = (datetime.now(UTC) - registered).days
            age_str = f"registered {age_days}d ago"
            tags.append(f"registered:{registered.date().isoformat()}")
            if 0 <= age_days < _NEW_DOMAIN_DAYS:
                verdict = Verdict.SUSPICIOUS
                tags.append("newly-registered")

        summary = f"RDAP: {age_str}" + (f" • {registrar}" if registrar else "")
        return ProviderResult(
            provider=self.name, verdict=verdict, summary=summary, tags=tags,
            raw={"registered": registered.isoformat() if registered else None,
                 "registrar": registrar, "status": statuses},
        )

    async def _query_ip(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        resp = await request_with_retry(
            client, "GET", _IP_URL.format(value=ioc.value),
            headers={"Accept": "application/rdap+json"},
        )
        if resp.status_code == 404:
            return ProviderResult(
                provider=self.name, verdict=Verdict.UNKNOWN, summary="No RDAP record"
            )
        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, summary=f"RDAP HTTP {resp.status_code}"
            )

        data = resp.json()
        net_name = data.get("name")
        country = data.get("country")
        handle = data.get("handle")

        org = None
        for ent in data.get("entities") or []:
            if "registrant" in (ent.get("roles") or []) or "administrative" in (
                ent.get("roles") or []
            ):
                vcard = ent.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) == 2:
                    for entry in vcard[1]:
                        if isinstance(entry, list) and entry and entry[0] == "fn":
                            org = str(entry[3]) if len(entry) > 3 else None
                            break
            if org:
                break

        tags = []
        if country:
            tags.append(f"country:{country}")
        if net_name:
            tags.append(f"netname:{net_name}")
        if handle:
            tags.append(f"handle:{handle}")

        pieces = [p for p in (net_name, org, country) if p]
        summary = "RDAP: " + " • ".join(pieces) if pieces else "RDAP: network registered"
        return ProviderResult(
            provider=self.name, verdict=Verdict.UNKNOWN, summary=summary, tags=tags,
            raw={"name": net_name, "country": country, "org": org, "handle": handle},
        )

    async def query(self, ioc: IOC, client: httpx.AsyncClient) -> ProviderResult:
        if ioc.type == IOCType.DOMAIN:
            return await self._query_domain(ioc, client)
        return await self._query_ip(ioc, client)
