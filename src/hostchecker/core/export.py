"""Export :class:`CheckResponse` into common threat-intel exchange formats.

Two formats are supported:

* **MISP event JSON** — drop-in compatible with the MISP REST API
  ``POST /events/add``. Each report becomes an ``Attribute`` with type
  inferred from the IOC kind, the aggregate verdict as the event's
  ``threat_level_id``, and per-IOC tags carrying score and provider
  metadata.
* **STIX 2.1 bundle** — a ``bundle`` containing one ``indicator`` SDO
  per report. Patterns follow the STIX 2.1 grammar; UUIDs are
  deterministic (``uuid5`` over a fixed namespace) so the same IOC
  always gets the same indicator ID.

Both functions are pure: same input → same output. No side effects, no
I/O, no clock except for ``created``/``modified`` timestamps and the
event date.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from .ioc import IOCType
from .models import CheckResponse, Verdict

# Stable namespace for deterministic STIX indicator IDs.
_HC_NAMESPACE = uuid.UUID("a7b8c9d0-1e2f-4a4b-8c6d-7e8f9a0b1c2d")

# IOCType → MISP attribute type / category.
_MISP_TYPE_MAP: dict[IOCType, tuple[str, str]] = {
    IOCType.IPV4: ("ip-dst", "Network activity"),
    IOCType.IPV6: ("ip-dst", "Network activity"),
    IOCType.DOMAIN: ("domain", "Network activity"),
    IOCType.URL: ("url", "Network activity"),
    IOCType.MD5: ("md5", "Payload delivery"),
    IOCType.SHA1: ("sha1", "Payload delivery"),
    IOCType.SHA256: ("sha256", "Payload delivery"),
}

# MISP threat levels: 1=High, 2=Medium, 3=Low, 4=Undefined.
_THREAT_LEVELS: dict[Verdict, str] = {
    Verdict.MALICIOUS: "1",
    Verdict.SUSPICIOUS: "2",
    Verdict.CLEAN: "3",
    Verdict.UNKNOWN: "4",
}


def _worst_verdict(response: CheckResponse) -> Verdict:
    """Return the most severe verdict across all reports."""
    order = (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.UNKNOWN, Verdict.CLEAN)
    seen = {r.aggregate_verdict for r in response.reports}
    for v in order:
        if v in seen:
            return v
    return Verdict.UNKNOWN


# ---------------------------------------------------------------------------
# MISP
# ---------------------------------------------------------------------------


def to_misp_event(
    response: CheckResponse,
    *,
    info: str = "host-checker scan",
    distribution: str = "0",
) -> dict[str, Any]:
    """Convert a CheckResponse into a MISP event JSON.

    The returned dict is wrapped under ``{"Event": {...}}`` so it can be
    POSTed directly to a MISP instance's ``/events/add`` endpoint.
    """
    now = datetime.now(UTC)
    threat_level = _THREAT_LEVELS.get(_worst_verdict(response), "4")

    attributes: list[dict[str, Any]] = []
    for report in response.reports:
        mapping = _MISP_TYPE_MAP.get(report.ioc_type)
        if not mapping:
            continue  # unsupported IOC type (e.g. CIDR) — skip in MISP export
        misp_type, category = mapping

        # Per-attribute tags: verdict, score, original provider tags.
        tags: list[dict[str, str]] = [
            {"name": f"host-checker:verdict={report.aggregate_verdict.value}"},
            {"name": f"host-checker:score={report.aggregate_score}"},
        ]
        provider_tags: set[str] = set()
        for r in report.results:
            provider_tags.update(r.tags)
        for t in sorted(provider_tags):
            tags.append({"name": t})

        # Comment: one-line per contributing provider.
        comment_lines = [
            f"Aggregate verdict: {report.aggregate_verdict.value}",
            f"Score: {report.aggregate_score}",
        ]
        if report.pivoted_from:
            comment_lines.append(f"Pivoted from: {report.pivoted_from}")
        for r in report.results:
            if r.summary and r.verdict not in (Verdict.SKIPPED, Verdict.ERROR):
                comment_lines.append(f"[{r.provider}] {r.verdict.value}: {r.summary}")

        attributes.append(
            {
                "type": misp_type,
                "category": category,
                "value": report.ioc,
                "to_ids": report.aggregate_verdict == Verdict.MALICIOUS,
                "distribution": "5",  # inherit from event
                "comment": " | ".join(comment_lines),
                "Tag": tags,
            }
        )

    return {
        "Event": {
            "info": info,
            "distribution": distribution,
            "threat_level_id": threat_level,
            "analysis": "2",  # completed
            "date": now.strftime("%Y-%m-%d"),
            "published": False,
            "Attribute": attributes,
        }
    }


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------


def _stix_pattern(ioc_type: IOCType, value: str) -> str | None:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return {
        IOCType.IPV4: f"[ipv4-addr:value = '{escaped}']",
        IOCType.IPV6: f"[ipv6-addr:value = '{escaped}']",
        IOCType.DOMAIN: f"[domain-name:value = '{escaped}']",
        IOCType.URL: f"[url:value = '{escaped}']",
        IOCType.MD5: f"[file:hashes.'MD5' = '{escaped}']",
        IOCType.SHA1: f"[file:hashes.'SHA-1' = '{escaped}']",
        IOCType.SHA256: f"[file:hashes.'SHA-256' = '{escaped}']",
    }.get(ioc_type)


_STIX_LABELS: dict[Verdict, list[str]] = {
    Verdict.MALICIOUS: ["malicious-activity"],
    Verdict.SUSPICIOUS: ["anomalous-activity"],
    Verdict.CLEAN: ["benign"],
    Verdict.UNKNOWN: ["unknown"],
}


def to_stix_bundle(response: CheckResponse) -> dict[str, Any]:
    """Convert a CheckResponse into a STIX 2.1 bundle dict.

    Each report becomes an ``indicator`` SDO. UUIDs are deterministic
    (``uuid5`` over a fixed namespace + IOC value) so re-exporting the
    same IOC always produces the same ID — useful when feeding TIPs
    that dedupe on STIX ID.
    """
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects: list[dict[str, Any]] = []

    for report in response.reports:
        pattern = _stix_pattern(report.ioc_type, report.ioc)
        if not pattern:
            continue

        indicator_uuid = uuid.uuid5(_HC_NAMESPACE, f"{report.ioc_type.value}:{report.ioc}")
        labels = _STIX_LABELS.get(report.aggregate_verdict, ["unknown"])

        description_lines = [
            f"Aggregate verdict: {report.aggregate_verdict.value}",
            f"Aggregate score: {report.aggregate_score}",
        ]
        if report.pivoted_from:
            description_lines.append(f"Pivoted from: {report.pivoted_from}")
        for r in report.results:
            if r.summary and r.verdict not in (Verdict.SKIPPED, Verdict.ERROR):
                description_lines.append(f"[{r.provider}] {r.verdict.value}: {r.summary}")

        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{indicator_uuid}",
                "created": now_iso,
                "modified": now_iso,
                "name": report.ioc,
                "description": "\n".join(description_lines),
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": now_iso,
                "labels": labels,
                "indicator_types": labels,
            }
        )

    return {"type": "bundle", "id": bundle_id, "objects": objects}
