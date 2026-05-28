"""Command-line interface for host-checker."""
from __future__ import annotations

import asyncio
import json
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Ensure providers self-register before the orchestrator looks them up.
from .. import providers  # noqa: F401
from ..core.export import to_misp_event, to_stix_bundle
from ..core.ioc import parse
from ..core.models import Verdict
from ..core.orchestrator import check_iocs
from ..core.registry import enabled_providers


class OutputFormat(str, Enum):
    TABLE = "table"
    JSON = "json"
    MISP = "misp"
    STIX = "stix"


app = typer.Typer(
    name="hostchecker",
    help="Query IPs, domains, URLs and hashes against multiple threat-intel sources.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


_VERDICT_STYLES = {
    Verdict.MALICIOUS: "bold red",
    Verdict.SUSPICIOUS: "bold yellow",
    Verdict.CLEAN: "green",
    Verdict.UNKNOWN: "dim",
    Verdict.ERROR: "red",
    Verdict.RATE_LIMITED: "magenta",
    Verdict.SKIPPED: "dim",
}


def _render(reports, providers_enabled: list[str], elapsed: float) -> None:
    console.print(
        Panel.fit(
            f"[bold]host-checker[/bold] • providers: "
            f"{', '.join(providers_enabled) or '[red]none enabled[/red]'} • "
            f"{elapsed:.2f}s",
            border_style="cyan",
        )
    )
    for report in reports:
        style = _VERDICT_STYLES.get(report.aggregate_verdict, "white")
        pivot_suffix = (
            f" • [italic]pivoted from {report.pivoted_from}[/italic]"
            if report.pivoted_from
            else ""
        )
        title = (
            f"[{style}]{report.aggregate_verdict.value.upper()}[/{style}] "
            f"• score {report.aggregate_score} • {report.ioc} ({report.ioc_type.value})"
            f"{pivot_suffix}"
        )
        table = Table(show_header=True, header_style="bold", expand=True)
        table.add_column("Provider", style="cyan", no_wrap=True)
        table.add_column("Verdict")
        table.add_column("Summary", overflow="fold")
        table.add_column("Tags", style="dim", overflow="fold")
        for r in report.results:
            v_style = _VERDICT_STYLES.get(r.verdict, "white")
            table.add_row(
                r.provider,
                f"[{v_style}]{r.verdict.value}[/{v_style}]",
                r.summary or "",
                ", ".join(r.tags),
            )
        console.print(Panel(table, title=title, border_style=style))


@app.command()
def check(
    targets: Annotated[
        list[str] | None,
        typer.Argument(
            help="IOCs to check. Comma/space separated; refanged automatically."
        ),
    ] = None,
    input_file: Annotated[
        Path | None,
        typer.Option("--input", "-i", help="Read IOCs from a file (one per line or CSV)."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output format: table (rich), json (CheckResponse), misp, stix.",
            case_sensitive=False,
        ),
    ] = OutputFormat.TABLE,
    output_json: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Shortcut for --format json (kept for backwards compatibility).",
        ),
    ] = False,
    provider_filter: Annotated[
        list[str] | None,
        typer.Option("--provider", "-p", help="Limit to these providers (repeatable)."),
    ] = None,
    allowlist_path: Annotated[
        Path | None,
        typer.Option("--allowlist", help="Allowlist file (overrides HC_ALLOWLIST_FILE)."),
    ] = None,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Bypass the on-disk result cache for this run.")
    ] = False,
    no_pivot: Annotated[
        bool,
        typer.Option(
            "--no-pivot",
            help="Don't resolve domain IOCs to IPs and check those too.",
        ),
    ] = False,
) -> None:
    """Run threat-intel checks against the given IOCs."""
    from ..config import settings as _settings
    from ..core.allowlist import Allowlist
    from ..core.cache import Cache

    text_parts: list[str] = []
    if targets:
        text_parts.extend(targets)
    if input_file:
        text_parts.append(input_file.read_text())
    if not text_parts:
        console.print("[red]No targets provided.[/red] Pass IOCs or use --input.")
        raise typer.Exit(code=2)

    iocs = parse(" ".join(text_parts))
    if not iocs:
        console.print("[red]No valid IOCs found in input.[/red]")
        raise typer.Exit(code=2)

    selected = enabled_providers()
    if provider_filter:
        wanted = {p.lower() for p in provider_filter}
        selected = [p for p in selected if p.name in wanted]
        if not selected:
            console.print(
                f"[red]None of the requested providers are enabled:[/red] {sorted(wanted)}"
            )
            raise typer.Exit(code=2)

    allowlist = Allowlist(allowlist_path or _settings.allowlist_file)
    cache = Cache(_settings.cache_dir, 0 if no_cache else _settings.cache_ttl)

    response = asyncio.run(
        check_iocs(
            iocs,
            providers=selected,
            allowlist=allowlist,
            cache=cache,
            auto_pivot=not no_pivot,
        )
    )

    # Resolve the effective format (legacy --json wins if set).
    effective = OutputFormat.JSON if output_json else output_format

    if effective == OutputFormat.JSON:
        sys.stdout.write(response.model_dump_json(indent=2) + "\n")
        return
    if effective == OutputFormat.MISP:
        sys.stdout.write(json.dumps(to_misp_event(response), indent=2) + "\n")
        return
    if effective == OutputFormat.STIX:
        sys.stdout.write(json.dumps(to_stix_bundle(response), indent=2) + "\n")
        return

    _render(response.reports, response.providers_enabled, response.elapsed_seconds)

    # Non-zero exit if anything came back malicious — useful in CI / scripts.
    if any(r.aggregate_verdict == Verdict.MALICIOUS for r in response.reports):
        raise typer.Exit(code=1)


@app.command("providers")
def providers_cmd() -> None:
    """List all known providers and their status."""
    from ..core.registry import all_provider_classes

    table = Table("Provider", "Supports", "Key required", "Enabled")
    enabled = {p.name for p in enabled_providers()}
    for cls in all_provider_classes():
        instance = cls()
        supports = ", ".join(t.value for t in sorted(cls.supported_types, key=lambda t: t.value))
        table.add_row(
            cls.name,
            supports,
            "yes" if cls.requires_key else "no",
            "✅" if instance.name in enabled else "❌",
        )
    console.print(table)


@app.command()
def serve(
    host: str = "127.0.0.1",
    port: int = 8000,
    reload: bool = False,
) -> None:
    """Start the FastAPI server."""
    import uvicorn

    uvicorn.run("hostchecker.api.app:app", host=host, port=port, reload=reload)


def main() -> None:  # pragma: no cover — console_scripts entry point
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
