# host-checker

[![CI](https://github.com/YOUR_USER/host-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USER/host-checker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

> Query IPs, domains, URLs and file hashes against multiple threat-intel sources in one shot — from a CLI, a self-hosted HTTP API or an interactive web UI.

`host-checker` is an open-source, self-hostable alternative to hosted IOC-checker tools that exposes more IOC types, accepts bulk input, runs locally so your targets never leave your machine, ships as a single Python package with a CLI **and** a FastAPI server **and** a web UI, exports to MISP and STIX, and uses an extensible provider architecture so adding a new threat-intel source is a single file.

---

## Features

- **Multiple IOC types**: IPv4, IPv6, CIDR, domain, URL, MD5/SHA1/SHA256.
- **Automatic refanging**: paste `evil[.]com`, `hxxp://`, `[dot]`, `(.)` — all normalised.
- **BYOK with sensible defaults**: keyless providers (Tor exit list, crt.sh, public URLhaus, IPinfo) work out of the box; premium ones unlock when you add a key.
- **Auto-pivot**: a domain check automatically fans out to its resolved IPs, linked back via `pivoted_from`.
- **Concurrent**: async fan-out across providers and IOCs with a configurable concurrency cap.
- **Three surfaces**: CLI for scripts and CI, JSON HTTP API for automation, and an interactive web UI for live triage. All powered by the same engine.
- **Aggregated, explainable score**: weighted-mean malice rolled into a 0–100 number plus a clear per-provider breakdown.
- **On-disk cache** with configurable TTL.
- **Local allowlist** so internal targets never leave your machine.
- **JSON output**: pipe into `jq`, MISP, TheHive, or your SIEM.
- **No vendor lock-in**: every result includes the raw provider payload.

## Supported providers

| Provider        | IOCs                                         | Requires key | Free tier        |
| --------------- | -------------------------------------------- | ------------ | ---------------- |
| `tor_exit`      | IPv4, IPv6                                   | no           | unlimited        |
| `crtsh`         | domain                                       | no           | unlimited        |
| `urlhaus`       | IPv4, domain, URL, MD5, SHA256               | no (key bumps limits) | abuse.ch    |
| `ipinfo`        | IPv4, IPv6                                   | no (key bumps limits) | 50k/month   |
| `virustotal`    | IP, domain, URL, MD5, SHA1, SHA256           | yes          | 500/day          |
| `abuseipdb`     | IPv4, IPv6                                   | yes          | 1 000/day        |
| `greynoise`     | IPv4                                         | yes          | 50/day community |
| `otx`           | IP, domain, URL, MD5, SHA1, SHA256           | yes          | unlimited        |
| `threatfox`     | IPv4, domain, URL, MD5, SHA1, SHA256         | yes (abuse.ch) | unlimited      |
| `malwarebazaar` | MD5, SHA1, SHA256                            | yes (abuse.ch) | unlimited      |
| `shodan`        | IPv4, IPv6                                   | yes          | $5 one-time      |

`abuse.ch` providers (`urlhaus`, `threatfox`, `malwarebazaar`) share a single Auth-Key — register once at <https://auth.abuse.ch/> and put it in `HC_ABUSECH_AUTH_KEY`.

Adding more sources is a single file — see [Adding a provider](#adding-a-provider).

---

## Install

```bash
git clone https://github.com/YOUR_USER/host-checker.git
cd host-checker
pip install -e ".[dev]"
cp .env.example .env  # then fill in the keys you have
```

Python 3.11+ required.

### Docker

```bash
# Run the web UI / API:
docker run --rm -p 8000:8000 \
  --env-file .env \
  -v "$PWD/.hostchecker-cache:/var/cache/hostchecker" \
  ghcr.io/YOUR_USER/host-checker:latest
# → open http://localhost:8000/

# Or run the CLI inside the container:
docker run --rm --env-file .env ghcr.io/YOUR_USER/host-checker:latest \
  hostchecker check 8.8.8.8 evil[.]com
```

## CLI usage

```bash
# Inline IOCs (comma- or space-separated; defanged forms accepted)
hostchecker check 8.8.8.8 evil[.]com hxxps://malicious[.]example/path

# From a file (one per line or CSV)
hostchecker check --input iocs.txt

# Machine-readable JSON
hostchecker check 1.1.1.1 --format json | jq .

# Export to threat-intel exchange formats
hostchecker check 1.2.3.4 evil.com --format misp > event.json     # MISP event
hostchecker check 1.2.3.4 evil.com --format stix > bundle.json   # STIX 2.1 bundle

# Only run specific providers
hostchecker check evil.com -p virustotal -p urlhaus

# List providers and their enablement status
hostchecker providers

# Start the HTTP API
hostchecker serve --host 0.0.0.0 --port 8000
```

Exit code is non-zero when any IOC's aggregate verdict is `malicious` — useful for CI gates.

## HTTP API

```bash
hostchecker serve &

curl -s http://localhost:8000/providers | jq .

curl -s -X POST http://localhost:8000/check \
     -H 'content-type: application/json' \
     -d '{"targets": ["8.8.8.8", "evil[.]com"]}' | jq .
```

Swagger UI lives at `/docs`, ReDoc at `/redoc`.

## Web UI

Open <http://localhost:8000/> after `hostchecker serve`. The page gives you:

- A textarea (with `localStorage` persistence — your last query survives reloads).
- Toggles for auto-pivot and bypass-cache.
- A collapsible panel listing every provider and whether it's currently enabled (greyed out when no key is configured).
- Results rendered as colour-coded cards by verdict (red / yellow / green / grey), with per-IOC counts, the aggregate score, and any `pivoted from` annotation.
- Each card expands to show the per-provider breakdown with a one-click **copy json** button on every row.
- Client-side filter (`malicious / suspicious / clean / unknown / all`) and sort (`score / verdict / IOC`).

Tailwind, htmx and Alpine.js are loaded from CDN — no build step. For air-gapped deployments you can vendor the three files into a `static/` directory and edit `templates/base.html` to point at the local copies; the rest of the app needs no changes.

## Configuration

All settings live in `.env` (see `.env.example`). Keys are read once at startup. Beyond credentials:

| Variable               | Default                | Meaning                                  |
| ---------------------- | ---------------------- | ---------------------------------------- |
| `HC_REQUEST_TIMEOUT`   | `15.0`                 | Per-request HTTP timeout (seconds).      |
| `HC_MAX_CONCURRENCY`   | `10`                   | Max in-flight provider queries.          |
| `HC_CACHE_DIR`         | `.hostchecker-cache`   | Local cache directory.                   |
| `HC_CACHE_TTL`         | `3600`                 | Cache TTL (seconds, `0` disables).       |
| `HC_AUTO_PIVOT`        | `true`                 | Resolve domain IOCs to IPs and check.    |
| `HC_PIVOT_LIMIT`       | `5`                    | Max IPs to pivot to per domain.          |
| `HC_ALLOWLIST_FILE`    | `(none)`               | Path to a plain-text allowlist file.     |

## Auto-pivot

When you check a domain, `host-checker` resolves it via DNS and **also checks each of the resulting IPs** against every supported provider, with a `pivoted_from` annotation linking them to the originating domain. This catches the common case where a domain looks clean on VirusTotal but its IPs are flagged by AbuseIPDB and Shodan reports a CVE.

```text
MALICIOUS • score 78.5 • evil.com (domain)
  ↳ vt: 12/63 engines flag malicious  …
SUSPICIOUS • score 42.0 • 1.2.3.4 (ipv4) • pivoted from evil.com
  ↳ abuseipdb: 87% confidence, 142 reports
  ↳ shodan: 8 open ports, 2 CVEs
```

Disable per-run with `--no-pivot`, globally with `HC_AUTO_PIVOT=false`. Cap the fan-out with `HC_PIVOT_LIMIT` (default `5`). Pivoted IPs respect the allowlist and the cache exactly like explicit IOCs.

## Caching

Provider results are cached on disk under `HC_CACHE_DIR` keyed by `(provider, ioc_type, ioc_value)`. Entries older than `HC_CACHE_TTL` are ignored, and errors / skipped results are never cached. Two ways to bypass it:

```bash
# Per-run, leaves the cache files in place:
hostchecker check 8.8.8.8 --no-cache

# Disable globally by setting:
HC_CACHE_TTL=0
```

Want to wipe? `rm -rf .hostchecker-cache/`.

## Allowlist

Create a plain text file with one IP, CIDR or domain per line. Lines starting with `#` are comments. Domain entries match the listed domain **and all its subdomains** (`example.com` allowlists `foo.bar.example.com`).

```text
# corp ranges
10.0.0.0/8
192.168.0.0/16
# our infra
example.com
mycompany.local
```

Point at it via the env var (`HC_ALLOWLIST_FILE=./allowlist.txt`) or on the command line (`--allowlist ./allowlist.txt`). Matching IOCs short-circuit as `CLEAN` and **never** reach any upstream provider — useful both for noise reduction and for keeping internal targets off third-party servers.

Hashes are intentionally never allowlist-able: a hash identifies a file, not infrastructure, and silencing a hash by accident is worse than a noisy alert.

## How the score works

Each provider returns a verdict in `{clean, suspicious, malicious, unknown, error, skipped}`. The aggregator:

1. Drops `error` and `skipped` from the calculation.
2. Maps verdicts to weights (`clean=0`, `suspicious=1`, `malicious=2`).
3. Multiplies by a per-provider weight (defaults in `core/aggregator.py:DEFAULT_WEIGHTS`).
4. Rescales to `[0, 100]`.

The thresholds for the final `aggregate_verdict` are intentionally simple — read `aggregate()` and tune for your environment.

## Adding a provider

Create `src/hostchecker/providers/your_source.py`:

```python
from ..config import settings
from ..core.ioc import IOC, IOCType
from ..core.models import ProviderResult, Verdict
from ..core.registry import register
from .base import Provider

@register
class YourSourceProvider(Provider):
    name = "your_source"
    supported_types = {IOCType.IPV4, IOCType.DOMAIN}
    requires_key = True

    def api_key(self) -> str | None:
        return settings.your_source_api_key

    async def query(self, ioc, client):
        resp = await client.get("https://example.com/api", params={"q": ioc.value})
        # … map response to a ProviderResult …
        return ProviderResult(provider=self.name, verdict=Verdict.CLEAN, summary="…")
```

Then:

1. Add the import to `providers/__init__.py`.
2. Add `your_source_api_key: str | None = None` to `config.py:Settings`.
3. Add the env var to `.env.example`.
4. Optionally tune its weight in `aggregator.py:DEFAULT_WEIGHTS`.

That's it — the registry picks it up automatically.

## Exports

Three machine-readable formats are produced from the same engine:

| Format  | What it is                                                              | Where                                             |
| ------- | ----------------------------------------------------------------------- | ------------------------------------------------- |
| `json`  | The native `CheckResponse` schema, raw provider payloads included.      | `--format json` · `POST /check` · UI button       |
| `misp`  | A MISP event JSON, ready for `POST /events/add` against a MISP instance.| `--format misp` · `POST /export/misp` · UI button |
| `stix`  | A STIX 2.1 bundle of `indicator` SDOs, with deterministic UUIDs.        | `--format stix` · `POST /export/stix` · UI button |

```bash
# Push a check result straight into a MISP instance:
hostchecker check 1.2.3.4 evil.com --format misp \
  | curl -s -X POST https://misp.example.org/events/add \
         -H "Authorization: $MISP_API_KEY" \
         -H "Accept: application/json" \
         -H "Content-Type: application/json" -d @-
```

In the web UI a **Download** row above the results lets you pull the same three formats with one click — useful for handing a triage to an analyst working in MISP / TheHive / OpenCTI.

## Roadmap

- SecurityTrails passive DNS, RDAP / WHOIS enrichment, AbuseIPDB v3 when available.
- Retry-with-backoff on 429s, per-provider rate-limit awareness.
- Optional sqlite cache backend (the current file-per-entry layout doesn't scale past tens of thousands of entries).
- Web UI: query history sidebar, side-by-side IOC comparison.

## License

MIT — see [LICENSE](./LICENSE).

## Disclaimer

This tool aggregates third-party data. Verdicts are best-effort and depend on the underlying providers. Always corroborate before acting on a single source.
