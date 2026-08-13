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

# Persistent state lives on the /data volume (created and owned by the
# non-root hunterx user below), so the CLI never falls back to a CWD-relative
# ./hunterx.db which would write to the ephemeral container layer.
ENV PATH="/opt/hunterx-venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HUNTERX_LOG_LEVEL=INFO \
    HUNTERX_DATABASE_URL="sqlite:////data/hunterx.db" \
    HUNTERX_DB_URL="sqlite:////data/hunterx.db"

WORKDIR /app

# Copy the self-contained venv (Python version-independent). Entry points and
# the full dependency tree are already inside it, so no hard-coded Python
# minor path is copied.
COPY --from=builder /opt/hunterx-venv/ /opt/hunterx-venv/

# Create non-root user and directories
RUN groupadd -r -g 999 hunterx && \
    useradd -r -g hunterx -u 999 -d /app -s /sbin/nologin hunterx && \
    mkdir -p /data /app/reports

# Set ownership and secure permissions
RUN chown -R hunterx:hunterx /app /data && \
    chmod -R o-rwx /app && \
    chmod 755 /app /data

USER hunterx

VOLUME ["/data"]

EXPOSE 8080

# Health check: verify the python runtime can import the hunterx v7 package.
# A plain import probe avoids invoking the CLI, which eagerly builds the
# platform and writes the database — a second process racing the container
# entrypoint on the same SQLite file would crash schema creation.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import hunterx" >/dev/null 2>&1 || exit 1

ENTRYPOINT ["hunterx"]
CMD ["--help"]
