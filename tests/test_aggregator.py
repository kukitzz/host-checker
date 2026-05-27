"""Tests for the scoring aggregator."""
from __future__ import annotations

from hostchecker.core.aggregator import aggregate
from hostchecker.core.ioc import IOC, IOCType
from hostchecker.core.models import IOCReport, ProviderResult, Verdict


def _report(*results: ProviderResult) -> IOCReport:
    r = IOCReport.empty(IOC(value="8.8.8.8", type=IOCType.IPV4, raw="8.8.8.8"))
    r.results = list(results)
    return r


def test_all_clean_gives_zero_score() -> None:
    r = _report(
        ProviderResult(provider="virustotal", verdict=Verdict.CLEAN),
        ProviderResult(provider="abuseipdb", verdict=Verdict.CLEAN),
    )
    aggregate(r)
    assert r.aggregate_score == 0.0
    assert r.aggregate_verdict == Verdict.CLEAN
    assert r.clean_count == 2
    assert r.providers_queried == 2


def test_one_malicious_flips_to_malicious() -> None:
    r = _report(
        ProviderResult(provider="virustotal", verdict=Verdict.MALICIOUS),
        ProviderResult(provider="abuseipdb", verdict=Verdict.CLEAN),
        ProviderResult(provider="greynoise", verdict=Verdict.CLEAN),
    )
    aggregate(r)
    assert r.malicious_count == 1
    assert r.aggregate_verdict == Verdict.MALICIOUS
    assert r.aggregate_score > 0


def test_errors_and_skips_are_excluded() -> None:
    r = _report(
        ProviderResult(provider="virustotal", verdict=Verdict.ERROR),
        ProviderResult(provider="abuseipdb", verdict=Verdict.SKIPPED),
        ProviderResult(provider="greynoise", verdict=Verdict.CLEAN),
    )
    aggregate(r)
    assert r.providers_queried == 1
    assert r.aggregate_verdict == Verdict.CLEAN


def test_suspicious_threshold() -> None:
    r = _report(
        ProviderResult(provider="virustotal", verdict=Verdict.SUSPICIOUS),
        ProviderResult(provider="abuseipdb", verdict=Verdict.SUSPICIOUS),
    )
    aggregate(r)
    assert r.aggregate_verdict == Verdict.SUSPICIOUS
    assert r.suspicious_count == 2
