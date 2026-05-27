"""FastAPI HTTP API for host-checker.

Two surfaces share the same orchestrator:

* **JSON API** — ``POST /check`` (existing). Stable, content-typed
  ``application/json``, used by scripts and external tools.
* **Web UI** — ``GET /`` serves an interactive page, ``POST /check/html``
  returns an HTML fragment for htmx to swap into the results area. No
  build step: Tailwind, htmx and Alpine.js are loaded from CDN.

No auth in the box — deploy behind a reverse proxy or add your own
middleware as needed.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .. import __version__
from .. import providers as _providers  # noqa: F401 — side-effect: register providers
from ..core.export import to_misp_event, to_stix_bundle
from ..core.ioc import parse
from ..core.models import CheckResponse
from ..core.orchestrator import check_iocs
from ..core.registry import all_provider_classes, enabled_providers

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


class CheckRequest(BaseModel):
    targets: list[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of IOCs. Each item may itself contain comma/whitespace-separated values.",
    )
    providers: list[str] | None = Field(
        default=None, description="Limit to these provider names. Default: all enabled."
    )
    auto_pivot: bool | None = Field(
        default=None,
        description="Resolve domain IOCs to IPs and check those too. Default: server setting.",
    )


app = FastAPI(
    title="host-checker",
    summary="Query IPs, domains, URLs and hashes against multiple threat-intel sources.",
    version=__version__,
)


def _all_providers_with_status() -> list[dict]:
    enabled = {p.name for p in enabled_providers()}
    return [
        {
            "name": cls.name,
            "enabled": cls.name in enabled,
            "requires_key": cls.requires_key,
            "supported_types": sorted(t.value for t in cls.supported_types),
        }
        for cls in sorted(all_provider_classes(), key=lambda c: c.name)
    ]


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/providers")
def providers_endpoint() -> dict:
    return {"providers": _all_providers_with_status()}


@app.post("/check", response_model=CheckResponse)
async def check_endpoint(req: CheckRequest) -> CheckResponse:
    iocs = parse(" ".join(req.targets))
    if not iocs:
        raise HTTPException(status_code=400, detail="No valid IOCs in input.")

    selected = enabled_providers()
    if req.providers:
        wanted = {p.lower() for p in req.providers}
        selected = [p for p in selected if p.name in wanted]
        if not selected:
            raise HTTPException(
                status_code=400,
                detail=f"None of the requested providers are enabled: {sorted(wanted)}",
            )
    return await check_iocs(iocs, providers=selected, auto_pivot=req.auto_pivot)


# ---------------------------------------------------------------------------
# Web UI
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request) -> HTMLResponse:
    all_providers = _all_providers_with_status()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "version": __version__,
            "all_providers": all_providers,
            "enabled_count": sum(1 for p in all_providers if p["enabled"]),
        },
    )


@app.post("/check/html", response_class=HTMLResponse, include_in_schema=False)
async def check_html(
    request: Request,
    targets: str = Form(...),
    providers: list[str] | None = Form(default=None),
    auto_pivot: bool = Form(default=False),
    no_cache: bool = Form(default=False),
) -> HTMLResponse:
    """Form-encoded counterpart of /check, returns an HTML fragment for htmx."""
    from ..config import settings as _settings
    from ..core.allowlist import Allowlist
    from ..core.cache import Cache

    iocs = parse(targets)
    if not iocs:
        return templates.TemplateResponse(
            request,
            "_results.html",
            {"error": "No valid IOCs found in input."},
            status_code=400,
        )

    selected = enabled_providers()
    if providers:
        wanted = {p.lower() for p in providers}
        selected = [p for p in selected if p.name in wanted]
        if not selected:
            return templates.TemplateResponse(
                request,
                "_results.html",
                {"error": f"None of the requested providers are enabled: {sorted(wanted)}"},
                status_code=400,
            )

    response = await check_iocs(
        iocs,
        providers=selected,
        allowlist=Allowlist(_settings.allowlist_file),
        cache=Cache(_settings.cache_dir, 0 if no_cache else _settings.cache_ttl),
        auto_pivot=auto_pivot,
    )
    return templates.TemplateResponse(
        request, "_results.html", {"response": response}
    )


# ---------------------------------------------------------------------------
# Export endpoints (shared by the JSON API and the Web UI)
# ---------------------------------------------------------------------------


_EXPORT_FORMATS = {"json", "misp", "stix"}


@app.post("/export/{fmt}", include_in_schema=True)
async def export_endpoint(
    fmt: str,
    targets: str = Form(...),
    providers: list[str] | None = Form(default=None),
    auto_pivot: bool = Form(default=False),
    no_cache: bool = Form(default=False),
) -> JSONResponse:
    """Run a check and return it formatted as ``json``, ``misp`` or ``stix``.

    Form-encoded — the Web UI's download buttons POST a regular ``FormData``,
    and ``curl -F ...`` works for scripted use. The response carries a
    ``Content-Disposition`` header so browsers prompt for a download.
    """
    from ..config import settings as _settings
    from ..core.allowlist import Allowlist
    from ..core.cache import Cache

    if fmt not in _EXPORT_FORMATS:
        raise HTTPException(
            status_code=400, detail=f"Unknown format. Choose one of: {sorted(_EXPORT_FORMATS)}"
        )

    iocs = parse(targets)
    if not iocs:
        raise HTTPException(status_code=400, detail="No valid IOCs in input.")

    selected = enabled_providers()
    if providers:
        wanted = {p.lower() for p in providers}
        selected = [p for p in selected if p.name in wanted]
        if not selected:
            raise HTTPException(
                status_code=400,
                detail=f"None of the requested providers are enabled: {sorted(wanted)}",
            )

    response = await check_iocs(
        iocs,
        providers=selected,
        allowlist=Allowlist(_settings.allowlist_file),
        cache=Cache(_settings.cache_dir, 0 if no_cache else _settings.cache_ttl),
        auto_pivot=auto_pivot,
    )

    if fmt == "misp":
        body: dict = to_misp_event(response)
    elif fmt == "stix":
        body = to_stix_bundle(response)
    else:  # json
        body = response.model_dump(mode="json")

    return JSONResponse(
        content=body,
        headers={
            "Content-Disposition": f'attachment; filename="hostchecker-{fmt}.json"',
        },
    )
