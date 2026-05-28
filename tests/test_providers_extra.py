"""Tests for the RDAP and SecurityTrails providers."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx

from hostchecker.core import http as http_module
from hostchecker.core.ioc import IOC, IOCType
from hostchecker.core.models import Verdict
from hostchecker.providers.rdap import RDAPProvider
from hostchecker.providers.securitytrails import SecurityTrailsProvider


async def _noop_sleep(_s: float) -> None:
    return None


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _dom(v: str) -> IOC:
    return IOC(value=v, type=IOCType.DOMAIN, raw=v)


def _ip(v: str) -> IOC:
    return IOC(value=v, type=IOCType.IPV4, raw=v)


# ---------- RDAP ----------------------------------------------------------


async def test_rdap_new_domain_is_suspicious() -> None:
    recent = (datetime.now(UTC) - timedelta(days=5)).isoformat()

    async def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "events": [{"eventAction": "registration", "eventDate": recent}],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "EvilRegistrar"]]],
                    }
                ],
                "status": ["client transfer prohibited"],
            },
        )

    async with _client(handler) as client:
        res = await RDAPProvider().query(_dom("evil.com"), client)
    assert res.verdict == Verdict.SUSPICIOUS
    assert any(t == "newly-registered" for t in res.tags)
    assert any(t.startswith("registrar:evilregistrar") for t in res.tags)


async def test_rdap_old_domain_is_unknown() -> None:
    old = (datetime.now(UTC) - timedelta(days=4000)).isoformat()

    async def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"events": [{"eventAction": "registration", "eventDate": old}], "entities": []},
        )

    async with _client(handler) as client:
        res = await RDAPProvider().query(_dom("old.com"), client)
    assert res.verdict == Verdict.UNKNOWN
    assert "newly-registered" not in res.tags


async def test_rdap_domain_404() -> None:
    async def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    async with _client(handler) as client:
        res = await RDAPProvider().query(_dom("nope.invalid"), client)
    assert res.verdict == Verdict.UNKNOWN
    assert "No RDAP record" in res.summary


async def test_rdap_ip_enrichment() -> None:
    async def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "name": "GOOGLE",
                "country": "US",
                "handle": "NET-8-8-8-0-1",
                "entities": [
                    {
                        "roles": ["registrant"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
                    }
                ],
            },
        )

    async with _client(handler) as client:
        res = await RDAPProvider().query(_ip("8.8.8.8"), client)
    assert res.verdict == Verdict.UNKNOWN
    assert "country:US" in res.tags
    assert "netname:GOOGLE" in res.tags
    assert "GOOGLE" in res.summary


async def test_rdap_supports_both_domain_and_ip() -> None:
    assert IOCType.DOMAIN in RDAPProvider.supported_types
    assert IOCType.IPV4 in RDAPProvider.supported_types
    assert RDAPProvider.requires_key is False


# ---------- SecurityTrails -----------------------------------------------


async def test_securitytrails_fast_flux_suspicious(monkeypatch) -> None:
    monkeypatch.setattr(http_module.asyncio, "sleep", _noop_sleep)
    # 15 distinct IPs across the history → over the fast-flux threshold.
    records = [{"values": [{"ip": f"1.2.3.{i}"}]} for i in range(15)]

    async def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"records": records})

    p = SecurityTrailsProvider()
    p.api_key = lambda: "fake"
    async with _client(handler) as client:
        res = await p.query(_dom("flux.com"), client)
    assert res.verdict == Verdict.SUSPICIOUS
    assert "fast-flux-suspect" in res.tags
    assert "historical_ips:15" in res.tags


async def test_securitytrails_few_ips_unknown(monkeypatch) -> None:
    monkeypatch.setattr(http_module.asyncio, "sleep", _noop_sleep)
    records = [{"values": [{"ip": "1.2.3.4"}]}, {"values": [{"ip": "1.2.3.5"}]}]

    async def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"records": records})

    p = SecurityTrailsProvider()
    p.api_key = lambda: "fake"
    async with _client(handler) as client:
        res = await p.query(_dom("stable.com"), client)
    assert res.verdict == Verdict.UNKNOWN
    assert "historical_ips:2" in res.tags


async def test_securitytrails_rate_limited(monkeypatch) -> None:
    monkeypatch.setattr(http_module.asyncio, "sleep", _noop_sleep)

    async def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    p = SecurityTrailsProvider()
    p.api_key = lambda: "fake"
    async with _client(handler) as client:
        res = await p.query(_dom("x.com"), client)
    assert res.verdict == Verdict.RATE_LIMITED


async def test_securitytrails_disabled_without_key() -> None:
    p = SecurityTrailsProvider()
    # No key configured by default in test env.
    assert p.is_enabled() == bool(p.api_key())
