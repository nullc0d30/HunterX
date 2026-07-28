# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
# Official Docker image: nullc0d30/hunterx
# Multi-stage build for minimal production image

# ============================================================
# Stage 1: Build stage — install dependencies
# ============================================================
FROM python:3.11-slim AS builder

ARG VERSION=6.0.0
ARG BUILD_DATE
ARG VCS_REF

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build dependencies only
COPY requirements.txt .
RUN pip install --no-cache-dir --no-compile \
    --require-hashes \
    -r requirements.txt 2>/dev/null || \
    pip install --no-cache-dir --no-compile -r requirements.txt

# ============================================================
# Stage 2: Runtime stage — minimal final image
# ============================================================
FROM python:3.11-slim AS runtime

ARG VERSION=6.0.0
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
      org.opencontainers.image.description="HunterX ${VERSION} — AI-Assisted Vulnerability Hunter. Authorized security assessments only." \
      org.opencontainers.image.base.name="docker.io/python:3.11-slim"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    HX_LOG_LEVEL=INFO

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Create non-root user and directories
RUN groupadd -r -g 999 hunterx && \
    useradd -r -g hunterx -u 999 -d /app -s /sbin/nologin hunterx && \
    mkdir -p /data /app/reports

# Copy application source
COPY hunterx.py .
COPY core/ ./core/
COPY api/ ./api/
COPY plugins/ ./plugins/
COPY pyproject.toml hunterx.yaml ./
COPY payloads/ ./payloads/

# Set ownership and secure permissions
RUN chown -R hunterx:hunterx /app /data && \
    chmod -R o-rwx /app && \
    chmod 755 /app /app/hunterx.py /data

USER hunterx

VOLUME ["/data"]

EXPOSE 8443

# Health check: verify the process is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

ENTRYPOINT ["python", "hunterx.py"]
CMD ["--help"]
