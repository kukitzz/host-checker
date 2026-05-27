"""IOC parsing, normalisation and validation.

Accepts a free-form string with comma / whitespace separated indicators,
applies common *refang* transforms (``hxxp`` → ``http``, ``[.]`` → ``.``)
and classifies each token as one of :class:`IOCType`.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class IOCType(str, Enum):
    """Recognised indicator types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"


HASH_TYPES = {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}
NETWORK_TYPES = {IOCType.IPV4, IOCType.IPV6, IOCType.CIDR}


@dataclass(frozen=True)
class IOC:
    """A normalised, classified indicator."""

    value: str
    type: IOCType
    raw: str  # original string before refanging


# ---------------------------------------------------------------------------
# Refanging
# ---------------------------------------------------------------------------

_REFANG_SUBSTITUTIONS: tuple[tuple[str, str], ...] = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    (" dot ", "."),
    ("[:]", ":"),
    ("[/]", "/"),
    ("[@]", "@"),
    ("[at]", "@"),
)

# Case-insensitive replacement for `hxxp[s]://` → `http[s]://`. Real-world
# reports mix `hxxp`, `hXXp`, `HXXP`, etc., so a regex is cleaner than
# enumerating every variant in the substitutions table.
_HXXP_RE = re.compile(r"(?i)\bhxxp(s?)://")


def refang(token: str) -> str:
    """Reverse common IOC obfuscation patterns used in threat reports."""
    out = token.strip()
    out = _HXXP_RE.sub(lambda m: f"http{m.group(1)}://", out)
    for needle, replacement in _REFANG_SUBSTITUTIONS:
        out = out.replace(needle, replacement)
    return out


# ---------------------------------------------------------------------------
# Type detection
# ---------------------------------------------------------------------------

_MD5_RE = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
_SHA1_RE = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)

# Conservative domain regex — labels of 1–63 chars, total ≤253, must contain a dot.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+"
    r"[A-Za-z]{2,63}$"
)


def detect_type(value: str) -> IOCType:
    """Classify a single already-refanged token."""
    v = value.strip()
    if not v:
        return IOCType.UNKNOWN

    # Hashes first — cheapest and unambiguous.
    if _SHA256_RE.match(v):
        return IOCType.SHA256
    if _SHA1_RE.match(v):
        return IOCType.SHA1
    if _MD5_RE.match(v):
        return IOCType.MD5

    # Networks (CIDR before plain IP because ip_network() also accepts hosts).
    if "/" in v and not v.startswith(("http://", "https://")):
        try:
            ipaddress.ip_network(v, strict=False)
            return IOCType.CIDR
        except ValueError:
            pass

    try:
        ip = ipaddress.ip_address(v)
        return IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
    except ValueError:
        pass

    # URLs require a scheme — `urlparse` is too permissive on its own.
    if v.lower().startswith(("http://", "https://", "ftp://")):
        parsed = urlparse(v)
        if parsed.netloc:
            return IOCType.URL

    if _DOMAIN_RE.match(v):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Split on commas, newlines or runs of whitespace. We keep this permissive
# because users paste from all kinds of sources.
_SPLIT_RE = re.compile(r"[,\s]+")


def parse(text: str) -> list[IOC]:
    """Parse a free-form string into a list of classified, deduped IOCs.

    Duplicates (after normalisation and lower-casing of hashes/domains) are
    removed, preserving first-seen order.
    """
    tokens = (t for t in _SPLIT_RE.split(text) if t)
    seen: set[tuple[IOCType, str]] = set()
    out: list[IOC] = []
    for raw_token in tokens:
        normalised = refang(raw_token)
        ioc_type = detect_type(normalised)
        if ioc_type == IOCType.UNKNOWN:
            # Still surface it so the caller can decide what to do.
            out.append(IOC(value=normalised, type=IOCType.UNKNOWN, raw=raw_token))
            continue
        canonical = (
            normalised.lower() if ioc_type in HASH_TYPES | {IOCType.DOMAIN} else normalised
        )
        key = (ioc_type, canonical)
        if key in seen:
            continue
        seen.add(key)
        out.append(IOC(value=canonical, type=ioc_type, raw=raw_token))
    return out
