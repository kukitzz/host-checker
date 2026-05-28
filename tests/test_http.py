"""Tests for the HTTP retry/backoff helper."""
from __future__ import annotations

from datetime import UTC

import httpx
import pytest

from hostchecker.core import http as http_module
from hostchecker.core.http import _backoff_delay, _parse_retry_after, request_with_retry

# ---------- Retry-After parsing ------------------------------------------


def test_parse_retry_after_seconds() -> None:
    assert _parse_retry_after("120") == 120.0
    assert _parse_retry_after("0") == 0.0


def test_parse_retry_after_none_and_garbage() -> None:
    assert _parse_retry_after(None) is None
    assert _parse_retry_after("soon") is None
    assert _parse_retry_after("") is None


def test_parse_retry_after_http_date_future() -> None:
    # A clearly-future date should yield a positive delay.
    from datetime import datetime, timedelta
    from email.utils import format_datetime

    future = datetime.now(UTC) + timedelta(seconds=30)
    delay = _parse_retry_after(format_datetime(future))
    assert delay is not None
    assert 20 < delay <= 31


def test_parse_retry_after_past_date_clamped_to_zero() -> None:
    from datetime import datetime, timedelta
    from email.utils import format_datetime

    past = datetime.now(UTC) - timedelta(seconds=30)
    assert _parse_retry_after(format_datetime(past)) == 0.0


# ---------- backoff ------------------------------------------------------


def test_backoff_grows_and_is_bounded() -> None:
    # With full jitter, value is in [0, base * 2^(attempt-1)].
    for attempt in range(1, 6):
        d = _backoff_delay(attempt, base=0.5, cap=30.0)
        assert 0 <= d <= min(30.0, 0.5 * (2 ** (attempt - 1)))


# ---------- request_with_retry -------------------------------------------


async def test_returns_200_without_retry(monkeypatch) -> None:
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await request_with_retry(client, "GET", "https://x/")
    assert resp.status_code == 200
    assert calls["n"] == 1


async def test_retries_on_429_then_succeeds(monkeypatch) -> None:
    # Make sleeps instant.
    monkeypatch.setattr(http_module.asyncio, "sleep", _noop_sleep)
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return httpx.Response(200, text="finally")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await request_with_retry(
            client, "GET", "https://x/", max_retries=3, backoff_base=0.01
        )
    assert resp.status_code == 200
    assert calls["n"] == 3


async def test_gives_up_after_max_retries_returns_last_429(monkeypatch) -> None:
    monkeypatch.setattr(http_module.asyncio, "sleep", _noop_sleep)
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(429)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await request_with_retry(
            client, "GET", "https://x/", max_retries=2, backoff_base=0.01
        )
    assert resp.status_code == 429
    assert calls["n"] == 3  # initial + 2 retries


async def test_retries_on_503(monkeypatch) -> None:
    monkeypatch.setattr(http_module.asyncio, "sleep", _noop_sleep)
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503 if calls["n"] == 1 else 200)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await request_with_retry(
            client, "GET", "https://x/", max_retries=3, backoff_base=0.01
        )
    assert resp.status_code == 200
    assert calls["n"] == 2


async def test_does_not_retry_on_404(monkeypatch) -> None:
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await request_with_retry(client, "GET", "https://x/", max_retries=3)
    assert resp.status_code == 404
    assert calls["n"] == 1


async def test_retries_on_network_error_then_succeeds(monkeypatch) -> None:
    monkeypatch.setattr(http_module.asyncio, "sleep", _noop_sleep)
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("boom")
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await request_with_retry(
            client, "GET", "https://x/", max_retries=2, backoff_base=0.01
        )
    assert resp.status_code == 200
    assert calls["n"] == 2


async def test_raises_if_all_attempts_network_error(monkeypatch) -> None:
    monkeypatch.setattr(http_module.asyncio, "sleep", _noop_sleep)

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("always down")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(httpx.HTTPError):
            await request_with_retry(
                client, "GET", "https://x/", max_retries=2, backoff_base=0.01
            )


async def _noop_sleep(_seconds: float) -> None:
    return None
