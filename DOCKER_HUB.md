# Docker Hub Metadata

**Image Name**: `nullc0d3/hunterx`

## Short Description
Safe, reasoning-based Red Team orchestration framework. Non-destructive vulnerability verification.

## Full Description

# HunterX - Reasoning-Based Red Team Companion

HunterX is a production-grade orchestration framework designed for professional Red Teams. Unlike traditional scanners that rely on volume and brute force, HunterX operates as a **reasoning engine**. It observes, hypothesizes, and verifies vulnerabilities using a strictly gated, 4-stage pipeline.

This tool is engineered for:
- **Safety**: Non-destructive verification only.
- **Stealth**: Human-like jitter, adaptive backoff, and low-noise profiling.
- **Accuracy**: Context-aware precision to eliminate false positives.

## Usage

### Basic Scan
```bash
docker run --rm -v $(pwd)/reports:/data nullc0d3/hunterx -u https://target.com -o /data
```

### Advanced Profile (Bug Bounty)
```bash
docker run --rm -v $(pwd)/reports:/data nullc0d3/hunterx -u https://target.com --profile bounty --auto -o /data
```

## Volumes
- `/data`: Map this volume to persist reports (JSON, HTML) and logs.

## Security
- Runs as non-root user `hunterx`.
- Minimal slim image base.
- No background services or exposed ports.

## Disclaimer
HunterX is a specialized tool for authorized security auditing. The authors accept no liability for misuse. Ensure you have explicit permission to test any target.
