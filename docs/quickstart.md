---
layout: default
title: Quickstart — HunterX Vulnerability Scanner
description: >-
  Install and run HunterX vulnerability scanner in 5 minutes. Covers pip
  installation, Docker deployment, CLI usage examples for Red Team operations,
  bug bounty hunting, and security assessment.
---

# Quickstart Guide

Install and run HunterX in 5 minutes.

---

## Prerequisites

- Python 3.11+
- pip
- (Optional) Docker

---

## Installation

### From Source

```bash
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
pip install -r requirements.txt
python hunterx.py --help
```

### Docker

```bash
docker pull nullc0d30/hunterx:latest
docker run --rm nullc0d30/hunterx:latest --help
```

---

## Your First Scan

### Basic Vulnerability Scan

```bash
python hunterx.py -u https://example.com --profile bounty
```

This runs a standard bug-bounty profile scan with medium stealth, 200+ detection signatures, response differential analysis, and contextual reasoning.

### Stealth Scan with Authentication

```bash
python hunterx.py -u https://example.com --profile gov --auth bearer --token mytoken
```

The `gov` profile enforces low-and-slow timing (5-15s delays), hard request cap (100), and auto-aborts on WAF detection.

### Multi-Target Scan

```bash
python hunterx.py -f targets.txt --preset stealth
```

---

## API Server Mode

```bash
python hunterx.py api --port 8443
```

Submit scan jobs via REST API:

```bash
curl -X POST http://localhost:8443/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "profile": "bounty"}'
```

See the [API documentation](api) for all endpoints.

---

## Docker Usage

```bash
# Mount reports volume
docker run --rm \
  -v $(pwd)/reports:/data \
  nullc0d30/hunterx:latest \
  -u https://example.com \
  --profile bounty \
  -o /data

# API mode with port mapping
docker run --rm -p 8443:8443 nullc0d30/hunterx:latest api --port 8443
```

See the [Docker guide](docker) for production deployment.

---

## Output

Reports are generated in:

- **Markdown** — Human-readable summary
- **JSON** — Machine-parsable findings
- **SARIF 2.1** — VS Code / GitHub CodeQL integration
- **HTML** — Visual dashboard
- **ZIP** — Evidence package with screenshots

---

## Next Steps

- [Features Overview](features) — Full capability breakdown
- [API Documentation](api) — REST API reference
- [Plugin Development](plugins) — Extend HunterX
- [Roadmap](roadmap) — Upcoming releases
