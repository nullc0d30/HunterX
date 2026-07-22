# HunterX Docker Guide

This guide details how to run **HunterX** as a secure, isolated container.
The Docker image is the recommended way to run HunterX in production environments.

## Quick Start

```bash
# Pull the image
docker pull nullc0d3/hunterx:latest

# Run a quick help check
docker run --rm nullc0d3/hunterx --help
```

## Production Architecture

The Docker container is engineered for **isolation** and **safety**:

- **User**: Runs as non-root user `hunterx` (UID 999).
- **Network**: Requires egress for target scanning. No ingress ports exposed.
- **Storage**: Maps `/data` volume for reports and logs.
- **Base**: `python:3.11-slim` (Minimal attack surface).

## Usage Commands

### Standard Scan (Bounty Profile)
Mount the current directory's `reports` folder to `/data` in the container.

```bash
docker run --rm \
    -v "$(pwd)/reports:/data" \
    nullc0d3/hunterx \
    -u https://target.com \
    --profile bounty \
    -o /data
```

### High-Stealth Operation
Run as a passive observer with extreme stealth.

```bash
docker run --rm \
    -v "$(pwd)/reports:/data" \
    nullc0d3/hunterx \
    -u https://target.com \
    --profile gov \
    --passive-only \
    -o /data
```

### Interactive CLI Mode
If you need to enter the container (not recommended for automation, but useful for debugging):

```bash
docker run --rm -it --entrypoint /bin/bash nullc0d3/hunterx
```
*Note: This will still drop you into the restricted `hunterx` user shell.*

## Security Notes

1.  **Non-Root**: The container does not have root privileges. You cannot install packages or modify system files.
2.  **Volume Permissions**: Ensure your host `reports` directory is writable by the container user or 'others' (`chmod o+w reports`).
3.  **Network**: The container needs `http/https` access to the target.

## Troubleshooting

**Permission Denied on /data**:
The container user `hunterx` likely doesn't have permissions to write to your host folder.
*Fix*: `mkdir -p reports && chmod 777 reports` before running.

**DNS Resolution Failures**:
Ensure Docker has access to working DNS servers.
*Fix*: Add `--dns 8.8.8.8` to your run command.
