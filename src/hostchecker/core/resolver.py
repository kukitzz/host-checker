"""DNS resolution used by the auto-pivot feature.

We deliberately use :func:`socket.getaddrinfo` rather than pulling in a
dedicated async DNS library: it's already in the stdlib, it honours the
system resolver and hosts file (handy for testing and for environments
with custom DNS), and wrapping it with :func:`asyncio.to_thread` is
plenty fast for the handful of lookups we ever do per run.
"""
from __future__ import annotations

import asyncio
import socket


async def resolve(host: str, limit: int = 5, timeout: float = 5.0) -> list[str]:
    """Resolve ``host`` to up to ``limit`` unique IP strings.

    Returns an empty list on any resolution error — the caller decides
    whether that's a problem.
    """

    def _do() -> list[str]:
        try:
            records = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError, OSError):
            return []
        seen: set[str] = set()
        out: list[str] = []
        for rec in records:
            ip = rec[4][0]
            if "%" in ip:  # strip IPv6 scope ID
                ip = ip.split("%", 1)[0]
            if ip in seen:
                continue
            seen.add(ip)
            out.append(ip)
            if len(out) >= limit:
                break
        return out

    try:
        return await asyncio.wait_for(asyncio.to_thread(_do), timeout=timeout)
    except TimeoutError:
        return []
