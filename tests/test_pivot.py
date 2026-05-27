"""Tests for DNS resolution and auto-pivot orchestration."""
from __future__ import annotations

from hostchecker.core import resolver as resolver_module
from hostchecker.core.allowlist import Allowlist
from hostchecker.core.cache import Cache
from hostchecker.core.ioc import IOCType, parse
from hostchecker.core.models import Verdict
from hostchecker.core.orchestrator import _expand_pivots, check_iocs

# ---------- _expand_pivots -------------------------------------------------


async def test_expand_pivots_resolves_domains(monkeypatch) -> None:
    async def fake_resolve(host: str, limit: int = 5) -> list[str]:
        return {"example.com": ["1.2.3.4", "5.6.7.8"]}.get(host, [])

    monkeypatch.setattr(resolver_module, "resolve", fake_resolve)
    # The orchestrator imports `resolve` into its own namespace, so patch
    # both names for safety.
    monkeypatch.setattr(
        "hostchecker.core.orchestrator.resolve", fake_resolve
    )

    iocs = parse("example.com")
    work = await _expand_pivots(iocs, pivot_limit=5)
    assert len(work) == 3  # original + 2 IPs
    types = [w[0].type for w in work]
    values = [w[0].value for w in work]
    assert IOCType.DOMAIN in types
    assert "1.2.3.4" in values
    assert "5.6.7.8" in values
    # Pivoted entries should carry the source domain.
    pivot_sources = {w[1] for w in work if w[1] is not None}
    assert pivot_sources == {"example.com"}


async def test_expand_pivots_deduplicates_against_originals(monkeypatch) -> None:
    async def fake_resolve(host: str, limit: int = 5) -> list[str]:
        return ["1.2.3.4"]

    monkeypatch.setattr("hostchecker.core.orchestrator.resolve", fake_resolve)

    # User already passed 1.2.3.4 explicitly, so the pivot must skip it.
    iocs = parse("example.com 1.2.3.4")
    work = await _expand_pivots(iocs, pivot_limit=5)
    assert len(work) == 2  # original domain + original IP, no duplicate IP


async def test_expand_pivots_noop_without_domains(monkeypatch) -> None:
    # Even if resolve would return something, no-domain input must skip it.
    async def fake_resolve(host: str, limit: int = 5) -> list[str]:  # pragma: no cover
        raise AssertionError("should not be called")

    monkeypatch.setattr("hostchecker.core.orchestrator.resolve", fake_resolve)

    work = await _expand_pivots(parse("1.2.3.4 8.8.8.8"), pivot_limit=5)
    assert all(w[1] is None for w in work)
    assert len(work) == 2


# ---------- check_iocs end-to-end with no providers ----------------------


async def test_check_iocs_disables_pivot(monkeypatch, tmp_path) -> None:
    async def fake_resolve(host: str, limit: int = 5) -> list[str]:  # pragma: no cover
        raise AssertionError("resolve should not be called when auto_pivot=False")

    monkeypatch.setattr("hostchecker.core.orchestrator.resolve", fake_resolve)

    resp = await check_iocs(
        parse("example.com"),
        providers=[],
        allowlist=Allowlist(),
        cache=Cache(tmp_path, 0),
        auto_pivot=False,
    )
    assert len(resp.reports) == 1
    assert resp.reports[0].pivoted_from is None


async def test_check_iocs_pivot_produces_linked_reports(monkeypatch, tmp_path) -> None:
    async def fake_resolve(host: str, limit: int = 5) -> list[str]:
        return ["1.2.3.4"]

    monkeypatch.setattr("hostchecker.core.orchestrator.resolve", fake_resolve)

    resp = await check_iocs(
        parse("example.com"),
        providers=[],
        allowlist=Allowlist(),
        cache=Cache(tmp_path, 0),
        auto_pivot=True,
    )
    assert len(resp.reports) == 2
    pivoted = [r for r in resp.reports if r.pivoted_from]
    assert len(pivoted) == 1
    assert pivoted[0].ioc == "1.2.3.4"
    assert pivoted[0].pivoted_from == "example.com"


# ---------- real resolver smoke test -------------------------------------


async def test_real_resolver_handles_bad_host() -> None:
    # An invalid hostname must return [] rather than raise.
    out = await resolver_module.resolve(
        "this-host-very-much-does-not-exist.invalid.", timeout=2.0
    )
    assert out == []


# ---------- allowlist still applies to pivoted IPs -----------------------


async def test_allowlist_short_circuits_pivoted_ips(monkeypatch, tmp_path) -> None:
    async def fake_resolve(host: str, limit: int = 5) -> list[str]:
        return ["10.0.0.5"]

    monkeypatch.setattr("hostchecker.core.orchestrator.resolve", fake_resolve)

    allowlist = Allowlist()
    import ipaddress
    allowlist.networks.append(ipaddress.ip_network("10.0.0.0/8"))

    resp = await check_iocs(
        parse("example.com"),
        providers=[],
        allowlist=allowlist,
        cache=Cache(tmp_path, 0),
        auto_pivot=True,
    )
    pivoted = next(r for r in resp.reports if r.pivoted_from)
    assert pivoted.aggregate_verdict == Verdict.CLEAN
    assert any("allowlisted" in (res.tags or []) for res in pivoted.results)
