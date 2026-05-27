"""Tests for MISP and STIX exporters."""
from __future__ import annotations

import re

import pytest

from hostchecker.core.export import to_misp_event, to_stix_bundle
from hostchecker.core.ioc import IOC, IOCType
from hostchecker.core.models import CheckResponse, IOCReport, ProviderResult, Verdict


def _report(
    ioc: str,
    ioc_type: IOCType,
    verdict: Verdict,
    score: float = 0.0,
    pivoted_from: str | None = None,
    provider_results: list[ProviderResult] | None = None,
) -> IOCReport:
    r = IOCReport.empty(IOC(value=ioc, type=ioc_type, raw=ioc))
    r.aggregate_verdict = verdict
    r.aggregate_score = score
    r.pivoted_from = pivoted_from
    r.results = provider_results or []
    return r


def _response(*reports: IOCReport) -> CheckResponse:
    return CheckResponse(
        reports=list(reports), providers_enabled=["virustotal"], elapsed_seconds=0.5
    )


# ---------- MISP ----------------------------------------------------------


def test_misp_event_basic_shape() -> None:
    resp = _response(_report("1.2.3.4", IOCType.IPV4, Verdict.MALICIOUS, score=80))
    out = to_misp_event(resp)
    assert "Event" in out
    event = out["Event"]
    assert event["info"] == "host-checker scan"
    # Worst verdict was malicious → threat_level_id 1.
    assert event["threat_level_id"] == "1"
    assert event["published"] is False
    assert len(event["Attribute"]) == 1
    attr = event["Attribute"][0]
    assert attr["type"] == "ip-dst"
    assert attr["value"] == "1.2.3.4"
    assert attr["to_ids"] is True  # malicious -> goes to IDS


def test_misp_picks_attribute_type_per_ioc() -> None:
    resp = _response(
        _report("evil.com", IOCType.DOMAIN, Verdict.SUSPICIOUS),
        _report("http://x/y", IOCType.URL, Verdict.MALICIOUS),
        _report("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5, Verdict.MALICIOUS),
        _report("e" * 64, IOCType.SHA256, Verdict.CLEAN),
    )
    types = [a["type"] for a in to_misp_event(resp)["Event"]["Attribute"]]
    assert types == ["domain", "url", "md5", "sha256"]


def test_misp_threat_level_uses_worst_verdict() -> None:
    resp = _response(
        _report("1.2.3.4", IOCType.IPV4, Verdict.CLEAN),
        _report("evil.com", IOCType.DOMAIN, Verdict.SUSPICIOUS),
    )
    assert to_misp_event(resp)["Event"]["threat_level_id"] == "2"  # medium


def test_misp_clean_only_does_not_send_to_ids() -> None:
    resp = _response(_report("8.8.8.8", IOCType.IPV4, Verdict.CLEAN))
    attr = to_misp_event(resp)["Event"]["Attribute"][0]
    assert attr["to_ids"] is False


def test_misp_tags_carry_verdict_and_score_and_provider_tags() -> None:
    pr = ProviderResult(
        provider="urlhaus", verdict=Verdict.MALICIOUS, tags=["malware:emotet", "exe"]
    )
    resp = _response(
        _report(
            "evil.com",
            IOCType.DOMAIN,
            Verdict.MALICIOUS,
            score=75.0,
            provider_results=[pr],
        )
    )
    tag_names = {t["name"] for t in to_misp_event(resp)["Event"]["Attribute"][0]["Tag"]}
    assert "host-checker:verdict=malicious" in tag_names
    assert "host-checker:score=75.0" in tag_names
    assert "malware:emotet" in tag_names
    assert "exe" in tag_names


def test_misp_pivot_appears_in_comment() -> None:
    resp = _response(
        _report("1.2.3.4", IOCType.IPV4, Verdict.MALICIOUS, pivoted_from="evil.com")
    )
    comment = to_misp_event(resp)["Event"]["Attribute"][0]["comment"]
    assert "Pivoted from: evil.com" in comment


def test_misp_skips_unsupported_ioc_types() -> None:
    resp = _response(_report("10.0.0.0/8", IOCType.CIDR, Verdict.SUSPICIOUS))
    assert to_misp_event(resp)["Event"]["Attribute"] == []


# ---------- STIX ----------------------------------------------------------


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def test_stix_bundle_shape() -> None:
    resp = _response(_report("1.2.3.4", IOCType.IPV4, Verdict.MALICIOUS))
    out = to_stix_bundle(resp)
    assert out["type"] == "bundle"
    assert out["id"].startswith("bundle--")
    assert _UUID_RE.match(out["id"][len("bundle--") :])
    assert len(out["objects"]) == 1


def test_stix_indicator_fields() -> None:
    resp = _response(_report("1.2.3.4", IOCType.IPV4, Verdict.MALICIOUS, score=80))
    obj = to_stix_bundle(resp)["objects"][0]
    assert obj["type"] == "indicator"
    assert obj["spec_version"] == "2.1"
    assert obj["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
    assert obj["pattern_type"] == "stix"
    assert obj["labels"] == ["malicious-activity"]
    assert obj["name"] == "1.2.3.4"


@pytest.mark.parametrize(
    "ioc_type, value, expected",
    [
        (IOCType.IPV4, "1.2.3.4", "[ipv4-addr:value = '1.2.3.4']"),
        (IOCType.IPV6, "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
        (IOCType.DOMAIN, "evil.com", "[domain-name:value = 'evil.com']"),
        (IOCType.URL, "http://x/y", "[url:value = 'http://x/y']"),
        (
            IOCType.MD5,
            "d41d8cd98f00b204e9800998ecf8427e",
            "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']",
        ),
        (
            IOCType.SHA256,
            "e" * 64,
            f"[file:hashes.'SHA-256' = '{'e' * 64}']",
        ),
    ],
)
def test_stix_patterns_per_ioc_type(
    ioc_type: IOCType, value: str, expected: str
) -> None:
    resp = _response(_report(value, ioc_type, Verdict.MALICIOUS))
    obj = to_stix_bundle(resp)["objects"][0]
    assert obj["pattern"] == expected


def test_stix_indicator_id_is_deterministic() -> None:
    a = to_stix_bundle(_response(_report("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS)))
    b = to_stix_bundle(_response(_report("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS)))
    # Bundle ID is random per call, but the indicator ID must match.
    assert a["objects"][0]["id"] == b["objects"][0]["id"]
    assert a["id"] != b["id"]


def test_stix_escapes_single_quotes_in_patterns() -> None:
    resp = _response(_report("a'b.com", IOCType.DOMAIN, Verdict.SUSPICIOUS))
    obj = to_stix_bundle(resp)["objects"][0]
    assert obj["pattern"] == "[domain-name:value = 'a\\'b.com']"


def test_stix_skips_unsupported_ioc_types() -> None:
    resp = _response(_report("10.0.0.0/8", IOCType.CIDR, Verdict.SUSPICIOUS))
    assert to_stix_bundle(resp)["objects"] == []
