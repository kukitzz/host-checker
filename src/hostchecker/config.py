"""Centralised configuration loaded from environment variables / .env file.

All provider API keys are prefixed with ``HC_`` to avoid clashing with
anything else the user has exported.
"""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="HC_",
        extra="ignore",
    )

    # Provider API keys (all optional).
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    greynoise_api_key: str | None = None
    otx_api_key: str | None = None
    abusech_auth_key: str | None = None
    shodan_api_key: str | None = None
    ipinfo_api_key: str | None = None

    # Runtime knobs.
    request_timeout: float = Field(default=15.0, description="Per-request HTTP timeout (s).")
    max_concurrency: int = Field(default=10, description="Max parallel provider queries.")
    cache_dir: str = Field(default=".hostchecker-cache", description="Local cache directory.")
    cache_ttl: int = Field(default=3600, description="Cache TTL in seconds (0 disables).")
    allowlist_file: str | None = Field(
        default=None,
        description="Optional path to an allowlist file (one IP/CIDR/domain per line).",
    )
    auto_pivot: bool = Field(
        default=True,
        description="Resolve domain IOCs to IPs and check those too.",
    )
    pivot_limit: int = Field(
        default=5, description="Max IPs to pivot to per domain."
    )


# Module-level singleton — providers and CLI import this directly.
settings = Settings()
