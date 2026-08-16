# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Powered Security Orchestration & Intelligence Platform
# Official Docker image: nullc0d30/hunterx
# Multi-stage build for minimal production image

# ============================================================
# Stage 1: Build stage — install the package into a dedicated venv
# ============================================================
FROM python:3.11-slim AS builder

ARG VERSION=7.0.0
ARG BUILD_DATE
ARG VCS_REF

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# A venv at a fixed, version-independent path means the runtime stage never
# needs to know the exact Python minor in `site-packages` — it works for 3.11,
# 3.12, 3.13 and 3.14 alike.
RUN python -m venv /opt/hunterx-venv

COPY . .

RUN /opt/hunterx-venv/bin/pip install --no-cache-dir --no-compile ".[api]"

# ============================================================
# Stage 2: Runtime stage — minimal final image
# ============================================================
FROM python:3.11-slim AS runtime

ARG VERSION=7.0.0
ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Ahmed Awad (NullC0d3)" \
      org.opencontainers.image.url="https://github.com/nullc0d30/HunterX" \
      org.opencontainers.image.documentation="https://nullc0d30.github.io/HunterX" \
      org.opencontainers.image.source="https://github.com/nullc0d30/HunterX" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="NullC0d3" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="HunterX" \
      org.opencontainers.image.description="HunterX ${VERSION} — AI-powered security orchestration & intelligence platform: plans, orchestrates, executes, validates, correlates and reports security assessments by integrating open-source security tools." \
      org.opencontainers.image.base.name="docker.io/python:3.11-slim"

# Persistent state lives in the application data directory inside the image
# (/opt/hunterx/data, created and owned by the non-root hunterx user below),
# exposed as a volume so database persistence survives container recreation.
# The CLI/API resolve the same logical configuration as a native install:
# <application root>/data/hunterx.db. HUNTERX_DATA_DIR pins that location and
# the app's path resolver (hunterx.config.paths) derives the URL from it.
# The shared security-tool directory (<data>/tools/bin) and Go bin directory
# come BEFORE the venv on PATH: a same-named Python package CLI inside the venv
# (e.g. the httpx package's console script) must never shadow a security tool
# the operator installs into the shared tool directory. The directories are
# optional; empty PATH entries are harmless.
ENV PATH="/opt/hunterx/tools/bin:/opt/hunterx/go/bin:/opt/hunterx-venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HUNTERX_LOG_LEVEL=INFO \
    HUNTERX_DATA_DIR="/opt/hunterx/data" \
    HUNTERX_DATABASE_URL="sqlite:////opt/hunterx/data/hunterx.db" \
    HUNTERX_DB_URL="sqlite:////opt/hunterx/data/hunterx.db"

WORKDIR /app

# Copy the self-contained venv (Python version-independent). Entry points and
# the full dependency tree are already inside it, so no hard-coded Python
# minor path is copied.
COPY --from=builder /opt/hunterx-venv/ /opt/hunterx-venv/

# Create non-root user and application data directory
RUN groupadd -r -g 999 hunterx && \
    useradd -r -g hunterx -u 999 -d /app -s /sbin/nologin hunterx && \
    mkdir -p /opt/hunterx/data /app/reports

# Set ownership and secure permissions: the hunterx user owns the data dir so
# SQLite can create/open /opt/hunterx/data/hunterx.db.
RUN chown -R hunterx:hunterx /app /opt/hunterx && \
    chmod -R o-rwx /app /opt/hunterx && \
    chmod 755 /app /opt/hunterx /opt/hunterx/data

USER hunterx

VOLUME ["/opt/hunterx/data"]

EXPOSE 8080

# Health check: verify the python runtime can import the hunterx v7 package.
# A plain import probe avoids invoking the CLI, which eagerly builds the
# platform and writes the database — a second process racing the container
# entrypoint on the same SQLite file would crash schema creation.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import hunterx" >/dev/null 2>&1 || exit 1

ENTRYPOINT ["hunterx"]
CMD ["--help"]
