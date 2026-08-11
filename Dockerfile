# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Powered Security Orchestration & Intelligence Platform
# Official Docker image: nullc0d30/hunterx
# Multi-stage build for minimal production image

# ============================================================
# Stage 1: Build stage — install the package
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

COPY . .

RUN pip install --no-cache-dir --no-compile "."

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

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HUNTERX_LOG_LEVEL=INFO

WORKDIR /app

# Copy installed Python packages and entry point from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

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

# Health check: verify the hunterx v7 runtime is functional
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD hunterx version >/dev/null 2>&1 || exit 1

ENTRYPOINT ["hunterx"]
CMD ["--help"]
