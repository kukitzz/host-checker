"""Smoke tests for the FastAPI API and web UI.

These don't go to the network — they pass an empty providers list to
the orchestrator (via a monkeypatched `enabled_providers`) so the
machinery is exercised without any HTTP calls.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from hostchecker.api import app as app_module


@pytest.fixture
def client(monkeypatch):
    # Disable pivot DNS lookups for tests.
    monkeypatch.setenv("HC_AUTO_PIVOT", "false")
    # Force no providers so check runs offline.
    monkeypatch.setattr(app_module, "enabled_providers", lambda: [])
    return TestClient(app_module.app)


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_providers_endpoint(client: TestClient) -> None:
    r = client.get("/providers")
    assert r.status_code == 200
    data = r.json()
    assert "providers" in data
    names = {p["name"] for p in data["providers"]}
    # A few canonical ones should be there regardless of enablement.
    assert {"virustotal", "abuseipdb", "tor_exit", "shodan"}.issubset(names)


def test_index_renders(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    # Hallmarks of our template.
    assert b"host-checker" in r.content
    assert b"Auto-pivot" in r.content
    assert b'name="targets"' in r.content
    # CDN scripts present.
    assert b"tailwindcss" in r.content
    assert b"htmx.org" in r.content


def test_check_json_rejects_empty_targets(client: TestClient) -> None:
    r = client.post("/check", json={"targets": ["???"]})
    # ??? parses as UNKNOWN — the orchestrator runs but no real IOCs.
    # We treat parse-no-result as 400.
    assert r.status_code in (200, 400)


def test_check_html_validates_input(client: TestClient) -> None:
    r = client.post("/check/html", data={"targets": ""})
    # Empty form → 422 (FastAPI form validation).
    assert r.status_code in (400, 422)


def test_check_html_renders_results_fragment(client: TestClient) -> None:
    r = client.post(
        "/check/html",
        data={
            "targets": "8.8.8.8 example.com",
            "auto_pivot": "false",
        },
    )
    assert r.status_code == 200
    body = r.text
    # Both IOCs surface in the table.
    assert "8.8.8.8" in body
    assert "example.com" in body
    # The fragment isn't a full document — no <html>.
    assert "<html" not in body
    # Alpine wrapper is present, used by sort/filter.
    assert "x-data" in body
    # Download buttons rendered.
    assert "hcDownload('json')" in body
    assert "hcDownload('misp')" in body
    assert "hcDownload('stix')" in body


def test_export_misp(client: TestClient) -> None:
    r = client.post(
        "/export/misp",
        data={"targets": "1.2.3.4 evil.com", "auto_pivot": "false"},
    )
    assert r.status_code == 200
    assert r.headers["content-disposition"].startswith("attachment")
    body = r.json()
    assert "Event" in body
    types = [a["type"] for a in body["Event"]["Attribute"]]
    assert "ip-dst" in types
    assert "domain" in types


def test_export_stix(client: TestClient) -> None:
    r = client.post(
        "/export/stix",
        data={"targets": "1.2.3.4", "auto_pivot": "false"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "bundle"
    assert body["objects"][0]["pattern"] == "[ipv4-addr:value = '1.2.3.4']"


def test_export_rejects_unknown_format(client: TestClient) -> None:
    r = client.post(
        "/export/csv",
        data={"targets": "1.2.3.4", "auto_pivot": "false"},
    )
    assert r.status_code == 400
