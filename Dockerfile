# Base Image: Python 3.11 Slim (Minimal size)
FROM python:3.11-slim

# Labels
LABEL maintainer="NullC0d3"
LABEL description="HunterX Product Edition - AI-Assisted Vulnerability Hunter"
LABEL version="3.0"

# Environment Variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Working Directory
WORKDIR /app

# Install System Dependencies (none needed for pure python logic, but good practice to clean apt)
RUN apt-get update && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -r hunterx && useradd -r -g hunterx hunterx

# Copy Requirements and Install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Application Code
COPY . .

# Create Directories for Volumes and Permissions
RUN mkdir -p /data/reports && \
    chown -R hunterx:hunterx /app && \
    chown -R hunterx:hunterx /data

# Switch to non-root user
USER hunterx

# Define Volume for Reports
VOLUME ["/data"]

# Entrypoint updates output dir to volume by default if not specified, 
# but user should pass -o /data/reports manually or we wrap it.
# Simplicity: Entrypoint is python hunterx.py
ENTRYPOINT ["python", "hunterx.py"]

# Default Arguments (Help)
CMD ["--help"]
