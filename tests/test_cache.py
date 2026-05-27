"""Tests for the on-disk result cache."""
from __future__ import annotations

import time
from pathlib import Path

from hostchecker.core.cache import Cache
from hostchecker.core.ioc import IOC, IOCType
from hostchecker.core.models import ProviderResult, Verdict


def _ioc() -> IOC:
    return IOC(value="8.8.8.8", type=IOCType.IPV4, raw="8.8.8.8")


def test_cache_disabled_when_ttl_zero(tmp_path: Path) -> None:
    cache = Cache(tmp_path, ttl=0)
    assert cache.enabled is False
    r = ProviderResult(provider="vt", verdict=Verdict.CLEAN)
    cache.put("vt", _ioc(), r)
    assert cache.get("vt", _ioc()) is None
    # The directory should not even be created when disabled.
    assert not (tmp_path / "vt_*").exists()


def test_cache_roundtrip(tmp_path: Path) -> None:
    cache = Cache(tmp_path, ttl=60)
    r = ProviderResult(provider="vt", verdict=Verdict.MALICIOUS, summary="bad")
    cache.put("vt", _ioc(), r)
    cached = cache.get("vt", _ioc())
    assert cached is not None
    assert cached.verdict == Verdict.MALICIOUS
    assert cached.summary == "bad"


def test_cache_keys_isolate_providers_and_iocs(tmp_path: Path) -> None:
    cache = Cache(tmp_path, ttl=60)
    a = ProviderResult(provider="vt", verdict=Verdict.MALICIOUS)
    b = ProviderResult(provider="abuseipdb", verdict=Verdict.CLEAN)
    cache.put("vt", _ioc(), a)
    cache.put("abuseipdb", _ioc(), b)
    assert cache.get("vt", _ioc()).verdict == Verdict.MALICIOUS
    assert cache.get("abuseipdb", _ioc()).verdict == Verdict.CLEAN
    # Different IOC should miss.
    other = IOC(value="1.1.1.1", type=IOCType.IPV4, raw="1.1.1.1")
    assert cache.get("vt", other) is None


def test_cache_expires(tmp_path: Path, monkeypatch) -> None:
    cache = Cache(tmp_path, ttl=1)
    cache.put("vt", _ioc(), ProviderResult(provider="vt", verdict=Verdict.CLEAN))
    # Capture real time before patching, otherwise the lambda recurses.
    later = time.time() + 10
    monkeypatch.setattr(time, "time", lambda: later)
    assert cache.get("vt", _ioc()) is None


def test_cache_never_stores_errors_or_skips(tmp_path: Path) -> None:
    cache = Cache(tmp_path, ttl=60)
    cache.put("vt", _ioc(), ProviderResult(provider="vt", verdict=Verdict.ERROR))
    cache.put("vt", _ioc(), ProviderResult(provider="vt", verdict=Verdict.SKIPPED))
    assert cache.get("vt", _ioc()) is None
