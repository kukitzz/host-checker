# syntax=docker/dockerfile:1.7

# ----- builder stage: install into a venv we'll copy out -----------------
FROM python:3.14-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Install build deps only — wheel-only install avoids needing gcc here.
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip wheel \
    && /opt/venv/bin/pip install .

# ----- runtime stage -----------------------------------------------------
FROM python:3.14-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    HC_CACHE_DIR=/var/cache/hostchecker

# Non-root user.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 1001 hostchecker \
    && mkdir -p /var/cache/hostchecker \
    && chown -R hostchecker:hostchecker /var/cache/hostchecker

COPY --from=builder /opt/venv /opt/venv

USER hostchecker
WORKDIR /home/hostchecker

EXPOSE 8000

# Healthcheck against the API's /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

# Default to the web UI / API; override for the CLI:
#   docker run --rm -it ghcr.io/YOUR_USER/host-checker hostchecker check 8.8.8.8
CMD ["hostchecker", "serve", "--host", "0.0.0.0", "--port", "8000"]
