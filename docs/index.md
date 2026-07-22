---
layout: default
title: HunterX — AI-Assisted Vulnerability Hunter
description: >-
  HunterX is an open-source, production-grade Red Team orchestration framework
  powered by a 4-stage reasoning engine for vulnerability assessment,
  penetration testing, and security research. Supports REST API, AI/ML
  analysis, WebSocket and GraphQL testing, OOB detection, and plugin system.
  Apache 2.0 licensed.
image: /assets/images/hunterx-social.png
---

# HunterX

**The AI-Assisted Vulnerability Hunter — Automated Decision Support for Offensive Operations**

HunterX is a production-grade [Red Team](https://en.wikipedia.org/wiki/Red_team) orchestration framework by **Ahmed Awad (NullC0d3)**. It acts as a reasoning engine that observes, hypothesizes, probes, and verifies vulnerabilities using a strictly gated 4-stage pipeline with extreme operational safety, explainability, and stealth.

Unlike traditional vulnerability scanners that rely on brute force and signature matching, HunterX builds a **baseline fingerprint** of the target, analyzes **response differentials**, considers **authentication state**, **operator profile**, and **contextual signals** before increasing confidence in a finding.

---

## Quick Navigation

| Resource | Description |
|----------|-------------|
| [Quickstart Guide](quickstart) | Install and run your first scan in 5 minutes |
| [Features Overview](features) | Full capability breakdown |
| [REST API Documentation](api) | FastAPI server, endpoints, job queue |
| [Docker Guide](docker) | Container deployment |
| [Plugin System](plugins) | Write custom detectors, reporters, hooks |
| [Roadmap](roadmap) | Upcoming features and releases |

---

## Key Capabilities

- **4-Stage Pipeline**: Passive Intel → Probe → Confirm → Verify
- **200+ Detection Signatures**: LFI, RCE, SQLi, SSTI, SSRF, XSS, Open Redirect, XXE
- **REST API Server**: FastAPI-based async scan jobs with health checks and job queue
- **AI/ML Analysis**: LLM integration (Ollama) for automated finding review; scikit-learn anomaly clustering
- **Protocol Testing**: WebSocket endpoint discovery, GraphQL introspection and batching
- **Authentication**: Basic, Bearer Token, Cookie Jar, Form Login
- **OOB Detection**: Blind XXE, SSRF, and RCE via collaborator callbacks
- **Time-Based Injection**: Blind SQLi/NoSQLi timing analysis
- **WAF Evasion**: 50+ WAF signatures, auto-abort, payload mutation engine
- **Plugin System**: Decorator-based detector, reporter, and hook plugins
- **Reporting**: Markdown, JSON, ZIP evidence, SARIF 2.1 (VS Code/GitHub CodeQL)
- **Docker**: Optimized 271MB multi-stage image, non-root user, OCI labels

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Standard vulnerability scan
python hunterx.py -u https://target.com --profile bounty

# Scan with AI analysis
python hunterx.py -u https://target.com --ai --ai-model llama3.2

# API server mode
python hunterx.py api --port 8443

# Docker
docker run --rm nullc0d30/hunterx:latest -u https://target.com -o /data
```

See the [Quickstart Guide](quickstart) for detailed setup instructions.

---

## Project Statistics

| Metric | Value |
|--------|-------|
| License | Apache 2.0 |
| Python | 3.11, 3.12, 3.13 |
| Tests | 76 (100% pass rate) |
| Lint | ruff — 0 errors |
| Docker Image | 271MB (multi-stage) |
| Signature Count | 200+ |
| Built-in Profiles | 3 (Internal, Bounty, Gov) |

---

## Citation

```bibtex
@software{hunterx2026,
  author = {Ahmed Awad (NullC0d3)},
  title = {HunterX: AI-Assisted Vulnerability Hunter},
  version = {4.0.1},
  year = {2026},
  license = {Apache-2.0},
  url = {https://github.com/nullc0d30/HunterX}
}
```

---

*HunterX — Safe, smart, community-driven security assessment. Apache 2.0 licensed.*
