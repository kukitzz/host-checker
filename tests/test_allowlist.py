"""Tests for the local allowlist."""
from __future__ import annotations

from pathlib import Path

from hostchecker.core.allowlist import Allowlist
from hostchecker.core.ioc import IOC, IOCType


def _ip(v: str) -> IOC:
    return IOC(value=v, type=IOCType.IPV4, raw=v)


def _dom(v: str) -> IOC:
    return IOC(value=v.lower(), type=IOCType.DOMAIN, raw=v)


def test_empty_allowlist_matches_nothing() -> None:
    a = Allowlist()
    assert _ip("8.8.8.8") not in a
    assert _dom("example.com") not in a


def test_loads_ips_and_cidrs(tmp_path: Path) -> None:
    f = tmp_path / "list"
    f.write_text("# my ranges\n10.0.0.0/8\n192.168.1.1\n")
    a = Allowlist(f)
    assert _ip("10.5.4.3") in a
    assert _ip("192.168.1.1") in a
    assert _ip("8.8.8.8") not in a


def test_loads_domains_and_matches_subdomains(tmp_path: Path) -> None:
    f = tmp_path / "list"
    f.write_text("example.com\nanother.org\n")
    a = Allowlist(f)
    assert _dom("example.com") in a
    assert _dom("foo.bar.example.com") in a
    assert _dom("another.org") in a
    assert _dom("notexample.com") not in a  # not a subdomain of example.com
    assert _dom("evil.com") not in a


def test_hashes_are_never_allowlisted(tmp_path: Path) -> None:
    f = tmp_path / "list"
    f.write_text("10.0.0.0/8\nexample.com\n")
    a = Allowlist(f)
    h = IOC(value="d41d8cd98f00b204e9800998ecf8427e", type=IOCType.MD5, raw="...")
    assert h not in a


def test_comments_and_blanks_ignored(tmp_path: Path) -> None:
    f = tmp_path / "list"
    f.write_text("\n# heading\n\n10.0.0.0/8\n\n")
    a = Allowlist(f)
    assert len(a) == 1
