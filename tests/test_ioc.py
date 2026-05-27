"""Tests for IOC parsing and classification."""
from __future__ import annotations

import pytest

from hostchecker.core.ioc import IOCType, detect_type, parse, refang


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("8.8.8.8", "8.8.8.8"),
        ("8.8.8[.]8", "8.8.8.8"),
        ("8.8.8(.)8", "8.8.8.8"),
        ("evil[.]com", "evil.com"),
        ("evil[dot]com", "evil.com"),
        ("hxxps://evil[.]com/path", "https://evil.com/path"),
        ("HXXP://EVIL.COM", "http://EVIL.COM"),
    ],
)
def test_refang(raw: str, expected: str) -> None:
    assert refang(raw) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("8.8.8.8", IOCType.IPV4),
        ("2001:db8::1", IOCType.IPV6),
        ("10.0.0.0/8", IOCType.CIDR),
        ("example.com", IOCType.DOMAIN),
        ("sub.example.co.uk", IOCType.DOMAIN),
        ("https://example.com/path?q=1", IOCType.URL),
        ("http://1.2.3.4:8080/", IOCType.URL),
        ("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCType.SHA1),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            IOCType.SHA256,
        ),
        ("not-an-ioc!@#", IOCType.UNKNOWN),
    ],
)
def test_detect_type(value: str, expected: IOCType) -> None:
    assert detect_type(value) == expected


def test_parse_mixed_input_dedupes_and_refangs() -> None:
    text = "8.8.8[.]8, 8.8.8.8 evil[.]com\nhxxps://malicious[.]example/path"
    out = parse(text)
    types = [(i.type, i.value) for i in out]
    assert (IOCType.IPV4, "8.8.8.8") in types
    assert (IOCType.DOMAIN, "evil.com") in types
    assert (IOCType.URL, "https://malicious.example/path") in types
    # dedup: only one entry for 8.8.8.8
    assert sum(1 for t, v in types if v == "8.8.8.8") == 1


def test_parse_lowercases_hashes_and_domains() -> None:
    text = "D41D8CD98F00B204E9800998ECF8427E Example.COM"
    out = parse(text)
    by_type = {i.type: i.value for i in out}
    assert by_type[IOCType.MD5] == "d41d8cd98f00b204e9800998ecf8427e"
    assert by_type[IOCType.DOMAIN] == "example.com"
