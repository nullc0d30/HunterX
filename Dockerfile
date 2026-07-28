# Copyright (c) 2026 Ahmed Awad (NullC0d3)
#
# HunterX — AI-Assisted Vulnerability Hunter

FROM python:3.11-slim AS runtime

LABEL maintainer="NullC0d3"
LABEL description="HunterX v4.0.1 — AI-Assisted Vulnerability Hunter"
LABEL version="4.0.1"
LABEL org.opencontainers.image.authors="Ahmed Awad (NullC0d3)"
LABEL org.opencontainers.image.vendor="NullC0d3"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.description="HunterX v4.0.1 — AI-Assisted Vulnerability Hunter. Authorized security assessments only."
LABEL org.opencontainers.image.source="https://github.com/nullc0d30/HunterX"
LABEL org.opencontainers.image.title="HunterX"
LABEL org.opencontainers.image.version="4.0.1"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user
RUN groupadd -r hunterx && useradd -r -g hunterx hunterx

# Copy source files
COPY hunterx.py .
COPY core/ ./core/
COPY api/ ./api/
COPY plugins/ ./plugins/
COPY pyproject.toml hunterx.yaml ./
COPY payloads/ ./payloads/

RUN mkdir -p /data/reports && \
    chown -R hunterx:hunterx /app && \
    chown -R hunterx:hunterx /data

USER hunterx

VOLUME ["/data"]

EXPOSE 8443

ENTRYPOINT ["python", "hunterx.py"]
CMD ["--help"]
