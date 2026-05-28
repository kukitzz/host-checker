"""On-disk cache for provider results, with pluggable backends.

Two backends share one interface (:class:`CacheBackend`):

* **file** (default) — one JSON file per ``(provider, ioc_type, value)``
  triple. Zero setup, human-inspectable, but slow to list/purge once you
  have tens of thousands of entries.
* **sqlite** — a single SQLite database. Scales to large IOC volumes,
  supports indexed lookups and a one-statement purge of expired rows.
  Opt in with ``HC_CACHE_BACKEND=sqlite``.

The public :class:`Cache` is a thin facade over whichever backend is
configured, so the orchestrator and tests don't care which is in use.
Transient verdicts (error / skipped / rate-limited) are never cached —
we want those retried on the next run.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import time
from abc import ABC, abstractmethod
from pathlib import Path

from .ioc import IOC
from .models import ProviderResult, Verdict

# Verdicts we refuse to cache because they're transient.
_NON_CACHEABLE = (Verdict.ERROR, Verdict.SKIPPED, Verdict.RATE_LIMITED)


def _key(provider: str, ioc: IOC) -> str:
    """Stable cache key for a (provider, IOC) pair."""
    return hashlib.sha256(
        f"{provider}|{ioc.type.value}|{ioc.value}".encode()
    ).hexdigest()


# ---------------------------------------------------------------------------
# Backend interface
# ---------------------------------------------------------------------------


class CacheBackend(ABC):
    """Storage backend for cached provider results."""

    @abstractmethod
    def get(self, key: str, ttl: int) -> ProviderResult | None: ...

    @abstractmethod
    def put(self, key: str, result: ProviderResult) -> None: ...

    @abstractmethod
    def purge_expired(self, ttl: int) -> int:
        """Delete entries older than ``ttl`` seconds. Returns count removed."""

    @abstractmethod
    def clear(self) -> int:
        """Delete all entries. Returns count removed."""

    @abstractmethod
    def count(self) -> int:
        """Total number of stored entries."""


# ---------------------------------------------------------------------------
# File backend
# ---------------------------------------------------------------------------


class FileCacheBackend(CacheBackend):
    def __init__(self, cache_dir: str | Path) -> None:
        self.dir = Path(cache_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.dir / f"{key[:40]}.json"

    def get(self, key: str, ttl: int) -> ProviderResult | None:
        path = self._path(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if time.time() - float(payload.get("cached_at", 0)) > ttl:
            return None
        with contextlib.suppress(Exception):  # corrupt entry
            return ProviderResult.model_validate(payload["result"])
        return None  # pragma: no cover

    def put(self, key: str, result: ProviderResult) -> None:
        with contextlib.suppress(OSError):
            self._path(key).write_text(
                json.dumps(
                    {"cached_at": time.time(), "result": result.model_dump(mode="json")}
                ),
                encoding="utf-8",
            )

    def purge_expired(self, ttl: int) -> int:
        removed = 0
        cutoff = time.time() - ttl
        for path in self.dir.glob("*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if float(payload.get("cached_at", 0)) < cutoff:
                    path.unlink()
                    removed += 1
            except (OSError, ValueError):
                # Corrupt / unreadable — remove it too.
                with contextlib.suppress(OSError):
                    path.unlink()
                    removed += 1
        return removed

    def clear(self) -> int:
        removed = 0
        for path in self.dir.glob("*.json"):
            with contextlib.suppress(OSError):
                path.unlink()
                removed += 1
        return removed

    def count(self) -> int:
        return sum(1 for _ in self.dir.glob("*.json"))


# ---------------------------------------------------------------------------
# SQLite backend
# ---------------------------------------------------------------------------


class SQLiteCacheBackend(CacheBackend):
    def __init__(self, cache_dir: str | Path, db_name: str = "cache.sqlite3") -> None:
        self.dir = Path(cache_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / db_name
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                key        TEXT PRIMARY KEY,
                cached_at  REAL NOT NULL,
                payload    TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_cached_at ON cache(cached_at)")
        self._conn.commit()

    def get(self, key: str, ttl: int) -> ProviderResult | None:
        row = self._conn.execute(
            "SELECT cached_at, payload FROM cache WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        cached_at, payload = row
        if time.time() - float(cached_at) > ttl:
            return None
        with contextlib.suppress(Exception):
            return ProviderResult.model_validate_json(payload)
        return None  # pragma: no cover

    def put(self, key: str, result: ProviderResult) -> None:
        with contextlib.suppress(sqlite3.Error):
            self._conn.execute(
                "INSERT OR REPLACE INTO cache (key, cached_at, payload) VALUES (?, ?, ?)",
                (key, time.time(), result.model_dump_json()),
            )
            self._conn.commit()

    def purge_expired(self, ttl: int) -> int:
        cutoff = time.time() - ttl
        cur = self._conn.execute("DELETE FROM cache WHERE cached_at < ?", (cutoff,))
        self._conn.commit()
        return cur.rowcount

    def clear(self) -> int:
        cur = self._conn.execute("DELETE FROM cache")
        self._conn.commit()
        return cur.rowcount

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0])

    def close(self) -> None:  # pragma: no cover — used in tests/teardown
        self._conn.close()


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------


def _make_backend(backend: str, cache_dir: str | Path) -> CacheBackend:
    if backend == "sqlite":
        return SQLiteCacheBackend(cache_dir)
    return FileCacheBackend(cache_dir)


class Cache:
    """Facade over a cache backend. TTL ``<= 0`` disables caching entirely."""

    def __init__(
        self,
        cache_dir: str | Path,
        ttl: int,
        backend: str = "file",
    ) -> None:
        self.ttl = ttl
        self.backend_name = backend
        self._backend: CacheBackend | None = (
            _make_backend(backend, cache_dir) if ttl > 0 else None
        )

    @property
    def enabled(self) -> bool:
        return self.ttl > 0 and self._backend is not None

    def get(self, provider: str, ioc: IOC) -> ProviderResult | None:
        if not self.enabled:
            return None
        assert self._backend is not None
        return self._backend.get(_key(provider, ioc), self.ttl)

    def put(self, provider: str, ioc: IOC, result: ProviderResult) -> None:
        if not self.enabled:
            return
        if result.verdict in _NON_CACHEABLE:
            return
        assert self._backend is not None
        self._backend.put(_key(provider, ioc), result)

    # ----- maintenance helpers (used by the `hostchecker cache` command) ---

    def purge_expired(self) -> int:
        if self._backend is None:
            return 0
        return self._backend.purge_expired(self.ttl)

    def clear(self) -> int:
        if self._backend is None:
            return 0
        return self._backend.clear()

    def count(self) -> int:
        if self._backend is None:
            return 0
        return self._backend.count()
