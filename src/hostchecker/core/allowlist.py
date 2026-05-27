"""Local allowlist: silence checks for IPs/CIDRs/domains you trust.

The allowlist file is plain text, one entry per line. Lines starting
with ``#`` and empty lines are ignored. Recognised entry types:

* IPv4 / IPv6 addresses and CIDR networks (matched via ``ipaddress``).
* Domains — exact and any **subdomain** of a listed parent match. So
  listing ``example.com`` allowlists ``foo.example.com`` too.

Hashes are intentionally never allowlisted: a hash is a content
identifier, not infrastructure, and ignoring a hash by accident is a
worse failure mode than a noisy alert.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

from .ioc import IOC, IOCType

_NetworkT = ipaddress.IPv4Network | ipaddress.IPv6Network


class Allowlist:
    def __init__(self, path: str | Path | None = None) -> None:
        self.networks: list[_NetworkT] = []
        self.domains: set[str] = set()
        if path:
            self.load(Path(path))

    def load(self, path: Path) -> None:
        if not path.exists():
            return
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            entry = raw_line.strip()
            if not entry or entry.startswith("#"):
                continue
            try:
                self.networks.append(ipaddress.ip_network(entry, strict=False))
                continue
            except ValueError:
                pass
            self.domains.add(entry.lower().lstrip("."))

    def __len__(self) -> int:
        return len(self.networks) + len(self.domains)

    def __contains__(self, ioc: IOC) -> bool:
        if ioc.type in (IOCType.IPV4, IOCType.IPV6):
            try:
                ip = ipaddress.ip_address(ioc.value)
            except ValueError:
                return False
            return any(ip in n for n in self.networks)

        if ioc.type == IOCType.DOMAIN:
            d = ioc.value.lower()
            parts = d.split(".")
            # Match domain itself and every parent suffix.
            return any(".".join(parts[i:]) in self.domains for i in range(len(parts)))

        return False
