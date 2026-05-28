"""HTTP request helper with retry/backoff for transient failures.

Provider modules call :func:`request_with_retry` instead of
``client.get/post`` directly so that we get uniform handling of:

* **429 Too Many Requests** — honours ``Retry-After`` (both seconds and
  HTTP-date forms); otherwise falls back to exponential backoff with
  jitter.
* **502, 503, 504** — transient upstream errors; same backoff policy.
* **Network errors** (DNS, connection reset, read timeout) — retried
  the same way.

Anything else (200, 4xx other than 429, etc.) is returned to the caller
on the first try.

The retry budget is bounded by :attr:`Settings.max_retries`; the total
wall-clock spent retrying is bounded by :attr:`Settings.request_timeout`
multiplied by the retry count, because every attempt also carries the
per-request timeout.
"""
from __future__ import annotations

import asyncio
import email.utils
import random
from datetime import UTC, datetime

import httpx

from ..config import settings

_RETRY_STATUS = frozenset({429, 502, 503, 504})


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a ``Retry-After`` header into seconds, if possible.

    The header accepts either a non-negative integer (seconds) or an
    HTTP-date. Returns ``None`` on anything we can't parse.
    """
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        # email.utils handles RFC 7231 IMF-fixdate, RFC 850 and asctime.
        dt = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    delta = (dt - datetime.now(UTC)).total_seconds()
    return max(0.0, delta)


def _backoff_delay(attempt: int, base: float, cap: float = 30.0) -> float:
    """Exponential backoff with full jitter, capped at ``cap`` seconds.

    ``attempt`` starts at 1 for the *first* retry, so the first sleep is
    in ``[0, base * 2)`` seconds.
    """
    return random.uniform(0, min(cap, base * (2 ** (attempt - 1))))


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_retries: int | None = None,
    backoff_base: float | None = None,
    **kwargs,
) -> httpx.Response:
    """Issue an HTTP request, retrying on transient failures.

    Returns the final :class:`httpx.Response` regardless of status, so
    callers still have the chance to inspect (e.g.) a final ``429`` and
    surface it as ``Verdict.RATE_LIMITED``.

    Raises :class:`httpx.HTTPError` only if every attempt raised a
    network-level error.
    """
    retries = settings.max_retries if max_retries is None else max_retries
    base = settings.retry_backoff_base if backoff_base is None else backoff_base

    last_exc: httpx.HTTPError | None = None
    response: httpx.Response | None = None

    for attempt in range(retries + 1):
        try:
            response = await client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            last_exc = exc
            response = None
            if attempt == retries:
                raise
            await asyncio.sleep(_backoff_delay(attempt + 1, base))
            continue

        if response.status_code not in _RETRY_STATUS or attempt == retries:
            return response

        # Decide how long to wait before the next attempt.
        retry_after = _parse_retry_after(response.headers.get("Retry-After"))
        delay = retry_after if retry_after is not None else _backoff_delay(attempt + 1, base)
        # Hard cap so a hostile Retry-After can't park us forever.
        await asyncio.sleep(min(delay, 60.0))

    # Defensive: loop always returns or raises, but mypy doesn't see it.
    if response is not None:  # pragma: no cover
        return response
    raise last_exc or httpx.HTTPError("request_with_retry exhausted with no response")
