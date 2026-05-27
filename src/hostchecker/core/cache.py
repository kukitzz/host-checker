"""On-disk cache for provider results.

Each `(provider, ioc_type, ioc_value)` triple maps to a JSON file under
:attr:`Cache.dir`. Entries older than :attr:`Cache.ttl` seconds (or any
entry at all if ``ttl <= 0``) are ignored. Errors and skipped results
are never cached — we want those to be retried on the next run.

The cache is intentionally trivial: one file per entry, JSON contents,
no locking. Concurrent writes to the same key would race, but that's
fine — last write wins and the data is idempotent.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import time
from pathlib import Path

from .ioc import IOC
from .models import ProviderResult, Verdict


class Cache:
    """A tiny JSON-file cache keyed by provider + IOC."""

    def __init__(self, cache_dir: str | Path, ttl: int) -> None:
        self.dir = Path(cache_dir)
        self.ttl = ttl
        if self.ttl > 0:
            self.dir.mkdir(parents=True, exist_ok=True)

    @property
    def enabled(self) -> bool:
        return self.ttl > 0

    def _path(self, provider: str, ioc: IOC) -> Path:
        digest = hashlib.sha256(
            f"{provider}|{ioc.type.value}|{ioc.value}".encode()
        ).hexdigest()[:32]
        return self.dir / f"{provider}_{digest}.json"

    def get(self, provider: str, ioc: IOC) -> ProviderResult | None:
        if not self.enabled:
            return None
        path = self._path(provider, ioc)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if time.time() - float(payload.get("cached_at", 0)) > self.ttl:
            return None
        with contextlib.suppress(Exception):  # corrupt cache entry
            return ProviderResult.model_validate(payload["result"])
        return None  # pragma: no cover

    def put(self, provider: str, ioc: IOC, result: ProviderResult) -> None:
        if not self.enabled:
            return
        # Don't cache transient failures or skips — we want retries.
        if result.verdict in (Verdict.ERROR, Verdict.SKIPPED):
            return
        path = self._path(provider, ioc)
        with contextlib.suppress(OSError):  # disk full, perms, etc.
            path.write_text(
                json.dumps(
                    {"cached_at": time.time(), "result": result.model_dump(mode="json")}
                ),
                encoding="utf-8",
            )
