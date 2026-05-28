"""Tests for the result cache, run against every backend."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from hostchecker.core.cache import (
    Cache,
    FileCacheBackend,
    SQLiteCacheBackend,
)
from hostchecker.core.ioc import IOC, IOCType
from hostchecker.core.models import ProviderResult, Verdict

BACKENDS = ["file", "sqlite"]


def _ioc(value: str = "8.8.8.8") -> IOC:
    return IOC(value=value, type=IOCType.IPV4, raw=value)


# ---------- facade behaviour (parametrised across backends) --------------


@pytest.mark.parametrize("backend", BACKENDS)
def test_cache_disabled_when_ttl_zero(tmp_path: Path, backend: str) -> None:
    cache = Cache(tmp_path, ttl=0, backend=backend)
    assert cache.enabled is False
    cache.put("vt", _ioc(), ProviderResult(provider="vt", verdict=Verdict.CLEAN))
    assert cache.get("vt", _ioc()) is None


@pytest.mark.parametrize("backend", BACKENDS)
def test_cache_roundtrip(tmp_path: Path, backend: str) -> None:
    cache = Cache(tmp_path, ttl=60, backend=backend)
    cache.put("vt", _ioc(), ProviderResult(provider="vt", verdict=Verdict.MALICIOUS, summary="bad"))
    cached = cache.get("vt", _ioc())
    assert cached is not None
    assert cached.verdict == Verdict.MALICIOUS
    assert cached.summary == "bad"


@pytest.mark.parametrize("backend", BACKENDS)
def test_cache_isolates_providers_and_iocs(tmp_path: Path, backend: str) -> None:
    cache = Cache(tmp_path, ttl=60, backend=backend)
    cache.put("vt", _ioc(), ProviderResult(provider="vt", verdict=Verdict.MALICIOUS))
    cache.put("abuseipdb", _ioc(), ProviderResult(provider="abuseipdb", verdict=Verdict.CLEAN))
    assert cache.get("vt", _ioc()).verdict == Verdict.MALICIOUS
    assert cache.get("abuseipdb", _ioc()).verdict == Verdict.CLEAN
    assert cache.get("vt", _ioc("1.1.1.1")) is None


@pytest.mark.parametrize("backend", BACKENDS)
def test_cache_expires(tmp_path: Path, backend: str, monkeypatch) -> None:
    cache = Cache(tmp_path, ttl=1, backend=backend)
    cache.put("vt", _ioc(), ProviderResult(provider="vt", verdict=Verdict.CLEAN))
    later = time.time() + 10
    monkeypatch.setattr(time, "time", lambda: later)
    assert cache.get("vt", _ioc()) is None


@pytest.mark.parametrize("backend", BACKENDS)
def test_cache_never_stores_transient_verdicts(tmp_path: Path, backend: str) -> None:
    cache = Cache(tmp_path, ttl=60, backend=backend)
    for v in (Verdict.ERROR, Verdict.SKIPPED, Verdict.RATE_LIMITED):
        cache.put("vt", _ioc(), ProviderResult(provider="vt", verdict=v))
        assert cache.get("vt", _ioc()) is None


@pytest.mark.parametrize("backend", BACKENDS)
def test_cache_count_clear_purge(tmp_path: Path, backend: str, monkeypatch) -> None:
    cache = Cache(tmp_path, ttl=100, backend=backend)
    cache.put("vt", _ioc("1.1.1.1"), ProviderResult(provider="vt", verdict=Verdict.CLEAN))
    cache.put("vt", _ioc("2.2.2.2"), ProviderResult(provider="vt", verdict=Verdict.CLEAN))
    assert cache.count() == 2

    # Purge with everything still fresh removes nothing.
    assert cache.purge_expired() == 0
    assert cache.count() == 2

    # Jump past the TTL → purge removes all.
    later = time.time() + 1000
    monkeypatch.setattr(time, "time", lambda: later)
    assert cache.purge_expired() == 2
    assert cache.count() == 0


@pytest.mark.parametrize("backend", BACKENDS)
def test_cache_clear_removes_all(tmp_path: Path, backend: str) -> None:
    cache = Cache(tmp_path, ttl=100, backend=backend)
    cache.put("vt", _ioc("1.1.1.1"), ProviderResult(provider="vt", verdict=Verdict.CLEAN))
    cache.put("otx", _ioc("2.2.2.2"), ProviderResult(provider="otx", verdict=Verdict.CLEAN))
    assert cache.count() == 2
    assert cache.clear() == 2
    assert cache.count() == 0


# ---------- backend selection --------------------------------------------


def test_facade_selects_sqlite_backend(tmp_path: Path) -> None:
    cache = Cache(tmp_path, ttl=60, backend="sqlite")
    assert isinstance(cache._backend, SQLiteCacheBackend)
    assert (tmp_path / "cache.sqlite3").exists()


def test_facade_selects_file_backend_by_default(tmp_path: Path) -> None:
    cache = Cache(tmp_path, ttl=60)
    assert isinstance(cache._backend, FileCacheBackend)


def test_unknown_backend_falls_back_to_file(tmp_path: Path) -> None:
    cache = Cache(tmp_path, ttl=60, backend="nonsense")
    assert isinstance(cache._backend, FileCacheBackend)


# ---------- sqlite-specific ----------------------------------------------


def test_sqlite_put_replaces_on_same_key(tmp_path: Path) -> None:
    be = SQLiteCacheBackend(tmp_path)
    ioc = _ioc()
    from hostchecker.core.cache import _key

    k = _key("vt", ioc)
    be.put(k, ProviderResult(provider="vt", verdict=Verdict.CLEAN))
    be.put(k, ProviderResult(provider="vt", verdict=Verdict.MALICIOUS))
    assert be.count() == 1  # replaced, not duplicated
    assert be.get(k, 60).verdict == Verdict.MALICIOUS
    be.close()
