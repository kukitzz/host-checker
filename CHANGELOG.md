# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- HTTP retry/backoff for transient upstream failures (429/502/503/504 and
  network errors), honouring `Retry-After`. Configurable via `HC_MAX_RETRIES`
  and `HC_RETRY_BACKOFF_BASE`.
- New `rate_limited` verdict, distinct from `error`, excluded from the
  aggregate score and rendered distinctly in the CLI and web UI.

## [0.1.0] — initial public release

### Added
- IOC parser with refanging for IPv4/IPv6, CIDR, domains, URLs, MD5/SHA1/SHA256.
- 11 threat-intel providers: `tor_exit`, `crt.sh`, `urlhaus`, `ipinfo`, `virustotal`, `abuseipdb`, `greynoise`, `otx`, `threatfox`, `malwarebazaar`, `shodan`.
- Async orchestrator with bounded concurrency and per-provider error isolation.
- Aggregated, explainable risk score in `[0, 100]` with configurable per-provider weights.
- On-disk result cache with TTL.
- Local allowlist with IP/CIDR and domain (+ subdomain) matching.
- Auto-pivot: domain checks fan out to resolved IPs automatically.
- CLI (`hostchecker check`) with rich output, JSON, MISP and STIX 2.1 export.
- JSON HTTP API (`/check`, `/providers`, `/export/{format}`, `/health`).
- Interactive web UI (htmx + Alpine + Tailwind, no build step) with filter / sort / per-row JSON copy and one-click MISP/STIX download.
- Docker image with healthcheck and non-root user.
- GitHub Actions CI (Python 3.11, 3.12) with lint and tests.
