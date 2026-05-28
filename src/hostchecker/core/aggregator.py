"""Aggregate per-provider results into a single risk score.

The scoring model is deliberately simple and explainable: every provider
gets a configurable weight (defaulting to 1.0), and each provider's verdict
is mapped to a numeric weight (clean=0, suspicious=1, malicious=2). The
final aggregate is the weighted-mean malice, rescaled to ``[0, 100]``.

This keeps the score easy to reason about — if you don't like the result
you can read ``IOCReport.results`` and decide for yourself.
"""
from __future__ import annotations

from .models import IOCReport, ProviderResult, Verdict, verdict_weight

# Provider-name → weight. Anything not listed defaults to 1.0. Tune to taste.
DEFAULT_WEIGHTS: dict[str, float] = {
    "virustotal": 1.5,
    "abuseipdb": 1.2,
    "otx": 1.2,
    "threatfox": 1.4,         # malware-only listings → very high signal
    "malwarebazaar": 1.5,     # presence == confirmed sample
    "urlhaus": 1.3,
    "greynoise": 1.0,
    "shodan": 0.8,            # vuln-driven, weaker malice signal
    "ipinfo": 0.5,            # mostly enrichment
    "tor_exit": 0.5,          # being a Tor exit isn't malicious by itself
    "crtsh": 0.1,             # informational
}


def aggregate(report: IOCReport, weights: dict[str, float] | None = None) -> IOCReport:
    """Populate the aggregate fields of ``report`` in place and return it."""
    w = {**DEFAULT_WEIGHTS, **(weights or {})}

    weighted_sum = 0.0
    weight_total = 0.0
    queried = 0

    for r in report.results:
        if r.verdict in (Verdict.SKIPPED, Verdict.ERROR, Verdict.RATE_LIMITED):
            continue
        queried += 1
        provider_weight = w.get(r.provider, 1.0)
        weighted_sum += verdict_weight(r.verdict) * provider_weight
        weight_total += provider_weight

        if r.verdict == Verdict.MALICIOUS:
            report.malicious_count += 1
        elif r.verdict == Verdict.SUSPICIOUS:
            report.suspicious_count += 1
        elif r.verdict == Verdict.CLEAN:
            report.clean_count += 1

    report.providers_queried = queried

    if weight_total == 0:
        report.aggregate_score = 0.0
        report.aggregate_verdict = Verdict.UNKNOWN
        return report

    # Max possible weighted_sum is weight_total * 2 (everyone says malicious).
    report.aggregate_score = round((weighted_sum / (weight_total * 2)) * 100, 2)

    if report.malicious_count >= 1 and report.aggregate_score >= 30:
        report.aggregate_verdict = Verdict.MALICIOUS
    elif report.aggregate_score >= 15 or report.suspicious_count >= 2:
        report.aggregate_verdict = Verdict.SUSPICIOUS
    elif report.clean_count > 0:
        report.aggregate_verdict = Verdict.CLEAN
    else:
        report.aggregate_verdict = Verdict.UNKNOWN

    return report


__all__ = ["aggregate", "DEFAULT_WEIGHTS", "ProviderResult"]
