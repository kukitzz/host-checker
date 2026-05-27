"""Pydantic models for provider outputs and aggregated reports."""
from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .ioc import IOC, IOCType


class Verdict(str, Enum):
    """Per-provider verdict for a given IOC."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"  # provider doesn't have data
    ERROR = "error"  # provider returned an error / was unreachable
    SKIPPED = "skipped"  # provider doesn't support this IOC type or has no key


# Numeric weights used to roll a verdict into the aggregate score.
_VERDICT_SCORE: dict[Verdict, int] = {
    Verdict.CLEAN: 0,
    Verdict.UNKNOWN: 0,
    Verdict.SKIPPED: 0,
    Verdict.ERROR: 0,
    Verdict.SUSPICIOUS: 1,
    Verdict.MALICIOUS: 2,
}


def verdict_weight(v: Verdict) -> int:
    return _VERDICT_SCORE[v]


class ProviderResult(BaseModel):
    """A single provider's response for a single IOC."""

    provider: str
    verdict: Verdict
    score: float | None = Field(
        default=None,
        description="Provider-native confidence/score in [0, 1], when available.",
    )
    summary: str | None = None
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] | None = Field(
        default=None, description="Raw provider payload (for power users)."
    )
    queried_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IOCReport(BaseModel):
    """Aggregated results for a single IOC across all providers."""

    ioc: str
    ioc_type: IOCType
    aggregate_score: float = Field(
        default=0.0,
        description="Weighted risk score in [0, 100]. Higher = more malicious.",
    )
    aggregate_verdict: Verdict = Verdict.UNKNOWN
    malicious_count: int = 0
    suspicious_count: int = 0
    clean_count: int = 0
    providers_queried: int = 0
    pivoted_from: str | None = Field(
        default=None,
        description="Original IOC this one was discovered from (e.g. via DNS resolution).",
    )
    results: list[ProviderResult] = Field(default_factory=list)

    @classmethod
    def empty(cls, ioc: IOC) -> IOCReport:
        return cls(ioc=ioc.value, ioc_type=ioc.type)


class CheckResponse(BaseModel):
    """Top-level response for the /check endpoint or `hostchecker check`."""

    reports: list[IOCReport]
    providers_enabled: list[str]
    elapsed_seconds: float
