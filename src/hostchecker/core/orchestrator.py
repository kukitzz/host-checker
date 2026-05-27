"""Async orchestrator: fan out IOCs to providers, gather and aggregate.

A single :class:`httpx.AsyncClient` is shared across the run so that
connection pooling and HTTP/2 work as expected. Each (IOC, provider)
pair becomes a task; the global concurrency limit caps how many are
in-flight at once.

Three extra layers wrap the provider calls:

* **Auto-pivot** — every domain IOC is resolved to its IPs (capped) and
  those IPs are checked too, with ``pivoted_from`` linking them to the
  originating domain.
* **Allowlist** — IOCs matching the configured allowlist short-circuit
  with a synthetic ``allowlist`` provider result and never reach any
  upstream service.
* **Cache** — per-(provider, IOC) JSON cache with TTL. Misses go to
  the network; hits return immediately.
"""
from __future__ import annotations

import asyncio
import time

import httpx

from ..config import settings
from ..providers.base import Provider
from .aggregator import aggregate
from .allowlist import Allowlist
from .cache import Cache
from .ioc import IOC, IOCType
from .models import CheckResponse, IOCReport, ProviderResult, Verdict
from .registry import enabled_providers
from .resolver import resolve


def _allowlisted_report(ioc: IOC, pivoted_from: str | None = None) -> IOCReport:
    """Build a short-circuit report for an allowlisted IOC."""
    report = IOCReport.empty(ioc)
    report.pivoted_from = pivoted_from
    report.results = [
        ProviderResult(
            provider="allowlist",
            verdict=Verdict.CLEAN,
            summary="Matched local allowlist; no upstream queries performed.",
            tags=["allowlisted"],
        )
    ]
    report.aggregate_verdict = Verdict.CLEAN
    report.aggregate_score = 0.0
    report.clean_count = 1
    report.providers_queried = 1
    return report


async def _query_one(
    provider: Provider,
    ioc: IOC,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    cache: Cache,
) -> ProviderResult:
    """Run a single provider against a single IOC with cache + backpressure."""
    if ioc.type not in provider.supported_types:
        return ProviderResult(provider=provider.name, verdict=Verdict.SKIPPED)

    if (cached := cache.get(provider.name, ioc)) is not None:
        return cached

    async with semaphore:
        try:
            result = await provider.query(ioc, client)
        except httpx.HTTPError as e:
            return ProviderResult(
                provider=provider.name,
                verdict=Verdict.ERROR,
                summary=f"HTTP error: {e!s}",
            )
        except Exception as e:  # pragma: no cover — defensive
            return ProviderResult(
                provider=provider.name,
                verdict=Verdict.ERROR,
                summary=f"Unhandled error: {e!s}",
            )

    cache.put(provider.name, ioc, result)
    return result


async def _expand_pivots(
    iocs: list[IOC], pivot_limit: int
) -> list[tuple[IOC, str | None]]:
    """Resolve every domain IOC to up to ``pivot_limit`` IPs.

    Returns a list of ``(ioc, pivoted_from)`` tuples comprising the
    original IOCs (with ``pivoted_from=None``) followed by any newly
    discovered IPs. Dedupes against the original set so explicitly-passed
    IOCs are never queried twice.
    """
    seen: set[tuple[IOCType, str]] = {(i.type, i.value) for i in iocs}
    work: list[tuple[IOC, str | None]] = [(i, None) for i in iocs]

    # Resolve all domains in parallel.
    domains = [i for i in iocs if i.type == IOCType.DOMAIN]
    if not domains:
        return work
    resolutions = await asyncio.gather(
        *(resolve(d.value, limit=pivot_limit) for d in domains)
    )

    for domain, ips in zip(domains, resolutions, strict=False):
        for ip in ips:
            ip_type = IOCType.IPV6 if ":" in ip else IOCType.IPV4
            key = (ip_type, ip)
            if key in seen:
                continue
            seen.add(key)
            work.append((IOC(value=ip, type=ip_type, raw=ip), domain.value))
    return work


async def check_iocs(  # noqa: PLR0913 — orchestration entry point
    iocs: list[IOC],
    providers: list[Provider] | None = None,
    allowlist: Allowlist | None = None,
    cache: Cache | None = None,
    auto_pivot: bool | None = None,
    pivot_limit: int | None = None,
) -> CheckResponse:
    """Run all configured providers against the given IOC list."""
    started = time.perf_counter()
    providers = providers if providers is not None else enabled_providers()
    allowlist = allowlist if allowlist is not None else Allowlist(settings.allowlist_file)
    cache = cache if cache is not None else Cache(settings.cache_dir, settings.cache_ttl)
    auto_pivot = settings.auto_pivot if auto_pivot is None else auto_pivot
    pivot_limit = settings.pivot_limit if pivot_limit is None else pivot_limit

    work_items: list[tuple[IOC, str | None]]
    if auto_pivot:
        work_items = await _expand_pivots(iocs, pivot_limit)
    else:
        work_items = [(i, None) for i in iocs]

    semaphore = asyncio.Semaphore(settings.max_concurrency)
    timeout = httpx.Timeout(settings.request_timeout)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        reports: list[IOCReport] = []
        for ioc, pivoted_from in work_items:
            if ioc in allowlist:
                reports.append(_allowlisted_report(ioc, pivoted_from))
                continue
            tasks = [_query_one(p, ioc, client, semaphore, cache) for p in providers]
            results = await asyncio.gather(*tasks)
            report = IOCReport.empty(ioc)
            report.results = list(results)
            report.pivoted_from = pivoted_from
            aggregate(report)
            reports.append(report)

    return CheckResponse(
        reports=reports,
        providers_enabled=[p.name for p in providers],
        elapsed_seconds=round(time.perf_counter() - started, 3),
    )
