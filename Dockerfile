FROM python:3.11-slim

LABEL maintainer="NullC0d3"
LABEL description="HunterX v4.0 — AI-Assisted Vulnerability Hunter"
LABEL version="4.0"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r hunterx && useradd -r -g hunterx hunterx

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data/reports && \
    chown -R hunterx:hunterx /app && \
    chown -R hunterx:hunterx /data

USER hunterx

VOLUME ["/data"]

EXPOSE 8443

ENTRYPOINT ["python", "hunterx.py"]
CMD ["--help"]
