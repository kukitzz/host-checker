# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — initial public release

Published on PyPI as `ioc-hostchecker` (import name and CLI command remain `hostchecker`).

### Added
- IOC parser with refanging for IPv4/IPv6, CIDR, domains, URLs, MD5/SHA1/SHA256.
- 13 threat-intel providers: `tor_exit`, `crtsh`, `urlhaus`, `ipinfo`, `rdap`,
  `virustotal`, `abuseipdb`, `greynoise`, `otx`, `threatfox`, `malwarebazaar`,
  `shodan`, `securitytrails`. Four work keyless (`tor_exit`, `crtsh`, `ipinfo`, `rdap`).
- Async orchestrator with bounded concurrency and per-provider error isolation.
- HTTP retry/backoff for transient failures (429/502/503/504 and network errors),
  honouring `Retry-After`. Configurable via `HC_MAX_RETRIES` / `HC_RETRY_BACKOFF_BASE`.
- Aggregated, explainable risk score in `[0, 100]` with configurable per-provider weights.
- Verdicts include a `rate_limited` state, distinct from `error`, excluded from scoring.
- Auto-pivot: domain checks fan out to resolved IPs automatically, linked via `pivoted_from`.
- Local allowlist with IP/CIDR and domain (+ subdomain) matching; allowlisted IOCs
  never leave the machine.
- Pluggable result cache with TTL: `file` (default) and `sqlite` backends, selectable
  via `HC_CACHE_BACKEND`. `hostchecker cache {status,purge,clear}` to maintain it.
- CLI (`hostchecker check`) with rich output and `--format json|misp|stix`.
- JSON HTTP API (`/check`, `/providers`, `/export/{format}`, `/health`).
- Interactive web UI (htmx + Alpine + Tailwind, no build step) with filter / sort /
  per-row JSON copy and one-click JSON/MISP/STIX download.
- MISP event and STIX 2.1 bundle exporters with deterministic indicator IDs.
- Docker image with healthcheck and non-root user.
- GitHub Actions CI (Python 3.11, 3.12) with lint and tests; tag-triggered release workflow.
