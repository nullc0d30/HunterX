---
Copyright (c) 2026 Ahmed Awad (NullC0d3)
All Rights Reserved.
---

# Changelog

All notable changes to HunterX are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [4.0] — 2026-07-22

### Added

- **REST API server** (FastAPI) — async scan jobs, health checks, job status polling
- **Authentication providers** — Basic, Bearer Token, Cookie Jar, Form Login
- **Enhanced detection** — 200+ vulnerability signatures
- **Time-based blind detection** — SQLi/NoSQLi timing analysis
- **Out-of-band (OOB) detection** — blind XXE/SSRF/RCE via collaborator
- **HTML DOM analysis** — structural response comparison
- **Payload mutation engine** — WAF evasion via encoding, SQL, LFI variants
- **Remote payload repository** — fetch latest payloads from external sources
- **Plugin system** — detector, reporter, and hook plugins via decorator API
- **YAML configuration** — `hunterx.yaml` with env var overrides (`HX_*`)
- **Scan presets** — quick, full, stealth profiles
- **SARIF 2.1 reporting** — GitHub CodeQL / VS Code integration
- **Structured JSON logging** — ELK/Loki compatible
- **Graceful shutdown** — SIGINT/SIGTERM handlers
- **WebSocket detection & testing** — endpoint discovery, message fuzzing
- **GraphQL introspection & batch/depth testing**
- **LLM analysis** — Ollama integration for automated finding analysis
- **Anomaly clustering** — scikit-learn DBSCAN for result deduplication
- **Centralized legal module** — `core/legal.py` with output metadata injection
- **Community documentation** — CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, SUPPORT
- **Issue/PR templates** — structured `.github/` templates
- **Roadmap, citation, release checklist**

### Changed

- CLI entry point fully rewritten for v4.0 flags
- Config system overhauled: dataclass-based with YAML + ENV + CLI overrides
- Docker image optimized: multi-stage build, reduced from 700MB to ~180MB
- HTTP client updated: `requests` 2.31.0 → 2.33.0 (3 CVEs fixed)
- CI/CD expanded: Python 3.11/3.12/3.13 matrix + Docker smoke test
- Test suite expanded: 29 → 41 tests

### Removed

- `setup.py` (replaced by modern `pyproject.toml`)

---

## [3.1] — 2026-07-20

### Fixed

- Thread safety issues in shared state (added `threading.Lock`)
- SSL verification default (on by default, `--insecure` opt-out)
- Rate limiting algorithm (token-bucket)
- WAF detection signatures (50+ signatures)

### Added

- Test suite with 29 pytest tests
- GitHub Actions CI pipeline (`test.yml`)
- Captcha detection and auto-backoff
- Operator profiles (internal, bounty, gov)
- Context-aware payload filtering
- Attack chain reasoning engine

---

## [3.0] — 2026-07-01

### Added

- Initial release of HunterX reasoning engine
- 4-stage orchestration pipeline (Passive → Probe → Confirm → Verify)
- 100+ vulnerability detection signatures
- Response differential analysis engine
- Safety-by-design guardrails (destructive payload blocklist)
- CLI entry point with 10+ flags
- Markdown/JSON/ZIP report generation
- Rich console visualization

---

*For a full list of commits, see [the GitHub repository](https://github.com/nullc0d30/HunterX/commits/main).*
