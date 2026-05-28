# Contributing to host-checker

Thanks for considering a contribution. The project is small enough that you should be able to read the whole codebase in an afternoon — start with `src/hostchecker/core/orchestrator.py`, that's the heart.

## Getting set up

```bash
git clone https://github.com/kukitzz/host-checker.git
cd host-checker
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env  # add any API keys you have
pre-commit install     # optional, not required
```

Then check that everything is green:

```bash
ruff check src tests
pytest -q
```

## What to send

- **Bug fixes** are always welcome. Please add a test that fails on `main` and passes with your change.
- **New providers** are the easiest place to start — see the "Adding a provider" section of the README. Keep the file small, the verdict mapping conservative, and add at least one test (mock the HTTP call with `pytest-httpx`).
- **New features** that change public behaviour (CLI flags, API endpoints, output formats): please open an issue first so we can agree on the shape.
- **UX/Web UI improvements** are welcome if they don't introduce a build step. The whole point is that you can `pip install` and have a working UI — no npm, no webpack.

## What we'll push back on

- Anything that exfiltrates IOCs without explicit user action. The tool's value is that it's self-hosted; sending IOCs to a "telemetry endpoint" of any kind is a hard no.
- Vendor lock-in. Every provider must work via its public API, with the key in `.env`.
- Removing the allowlist or making it less prominent — it's load-bearing for OPSEC.

## Style

- We use `ruff` with `pyproject.toml`'s config; just run `ruff check --fix .` and `ruff format .`.
- Type hints are encouraged but not enforced. `mypy` runs in CI as advisory.
- Tests use `pytest` (async tests with `pytest-asyncio`, HTTP mocking with `pytest-httpx`).
- Commits should be small and atomic. Squash before merging.

## Releasing

Maintainers only:

1. Update `CHANGELOG.md` and `pyproject.toml` version.
2. `git tag v0.X.Y && git push --tags`.
3. The release workflow uploads to PyPI and builds a Docker image to GHCR.
