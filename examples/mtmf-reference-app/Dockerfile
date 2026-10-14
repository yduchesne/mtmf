# MTMF reference application image (PR 20A).
#
# DEVELOPMENT ACCEPTANCE ONLY. Builds the independent example distribution on
# top of the local MTMF API/client source. It installs no mtmf-core,
# mtmf-service, PostgreSQL, or migration dependency: the reference app talks to
# MTMF only through the official HTTP client.
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Public runtime dependencies first for cache friendliness.
RUN pip install --no-cache-dir \
    "fastapi>=0.115" \
    "httpx>=0.28,<0.29" \
    "pyjwt[crypto]>=2.13,<3" \
    "uvicorn>=0.30"

# Install the official API/client and the example itself from the local tree.
COPY packages/mtmf-api /build/packages/mtmf-api
COPY packages/mtmf-client /build/packages/mtmf-client
COPY examples/mtmf-reference-app /build/examples/mtmf-reference-app
RUN pip install --no-cache-dir --no-deps \
    /build/packages/mtmf-api \
    /build/packages/mtmf-client \
    /build/examples/mtmf-reference-app

# The reference app owns its documents in a dedicated SQLite volume. It runs as
# an unprivileged user; the fixture loader is executed in the same container as
# that user. The privileged initializer hands off the client secret with that
# ownership (see scripts/pr20a-initialize.py).
RUN useradd --uid 10001 --no-create-home --user-group app \
    && mkdir -p /data \
    && chown app:app /data

USER app

EXPOSE 8080
CMD ["python", "-m", "mtmf_reference_app"]
