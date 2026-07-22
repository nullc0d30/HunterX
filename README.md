# HunterX v4.0
**The AI-Assisted Vulnerability Hunter — Automated Decision Support for Offensive Operations**

HunterX is a production-grade Red Team orchestration framework by **NullC0d3**. It acts as a reasoning engine that observes, hypothesizes, probes, and verifies vulnerabilities using a strictly gated 4-stage pipeline with extreme operational safety, explainability, and stealth.

---

## v4.0 What's New

| Track | Feature | Status |
|-------|---------|--------|
| **1** | REST API server (FastAPI) — async scan jobs, health checks | Done |
| **2** | Auth support — Basic, Bearer Token, Cookie Jar, Form Login | Done |
| **3** | Enhanced detection — 200+ signatures, time-based, OOB, HTML DOM analysis | Done |
| **4** | Payload intelligence — mutation engine, remote payload repo, context-aware selection | Done |
| **5** | Plugin system — detector plugins, reporter plugins, post-scan hooks | Done |
| **6** | Config overhaul — YAML config file, env vars (`HX_*`), scan presets | Done |
| **7** | Reporting — SARIF format (VS Code/GitHub CodeQL), CSV export via plugins | Done |
| **8** | DevOps — graceful shutdown, structured JSON logging, pyproject.toml, Docker | Done |
| **9** | Protocol expansion — WebSocket detection, GraphQL introspection, batch/depth testing | Done |
| **10** | AI/ML — LLM analysis (Ollama), anomaly clustering (scikit-learn), auto-remediation | Done |

---

## Quick Start

```bash
pip install -r requirements.txt

# Standard scan
python hunterx.py -u http://target.com --profile bounty

# Stealth scan with auth
python hunterx.py -u http://target.com --profile gov --auth bearer --token mytoken

# API server mode
python hunterx.py api --port 8443

# With AI analysis (requires Ollama)
python hunterx.py -u http://target.com --ai --ai-model llama3.2

# Multi-target with preset
python hunterx.py -f targets.txt --preset stealth

# SARIF output
python hunterx.py -u http://target.com --sarif
```

---

## Full Project Audit (v4.0)

### Code Quality

| Metric | Value |
|--------|-------|
| **Total source files** | 38 Python files |
| **Lines of code** | ~5,200 (core) + ~500 (tests) + ~200 (plugins) |
| **Test count** | 41 pytest tests |
| **Test pass rate** | 100% |
| **Lint status** | ruff — all checks passed |
| **Python versions** | 3.11+ |
| **External dependencies** | 7 (requests, rich, dataclasses-json, pyyaml, jsonschema, websocket-client, beautifulsoup4) |
| **Optional dependencies** | lxml, fastapi, uvicorn, ollama, scikit-learn, numpy |

### Architecture

```
hunterx.py                     # CLI entry point (v4.0 — full rewrite)
core/
├── engine.py                  # Orchestration engine (290 lines)
├── config.py                  # YAML + env var config system
├── session.py                 # Stealth HTTP with auth support
├── detector.py                # 200+ vulnerability signatures
├── classifier.py              # Payload classification + guardrails
├── diff.py                    # Response differential analysis
├── fingerprint.py             # Baseline fingerprinting
├── profiles.py                # Operator profiles
├── context.py                 # Target context analysis
├── reasoning.py               # Attack chain inference
├── waf.py                     # WAF detection & evasion
├── passive.py                 # Passive intelligence
├── report.py                  # Markdown/JSON/ZIP reports
├── sarif_reporter.py          # SARIF 2.1 output
├── visualizer.py              # CLI/Web dashboard
├── trace.py                   # Event trace logging
├── memory.py                  # Session memory
├── impact.py                  # Impact analysis
├── payload_manager.py         # Multi-Armed Bandit ranking
├── mutation_engine.py         # Payload mutation for WAF evasion
├── time_based.py              # Blind time-based detection
├── oob.py                     # Out-of-band detection
├── html_analyzer.py           # DOM structural analysis
├── plugin_loader.py           # Plugin discovery system
├── payload_repo.py            # Remote payload fetching
│
├── auth/                      # Authentication providers
│   └── providers.py           # Basic, Bearer, Cookie, Form
│
├── protocols/                 # Protocol expansion
│   ├── websocket.py           # WebSocket detection & testing
│   └── graphql.py             # GraphQL introspection & batching
│
└── ai/                        # AI/ML modules
    ├── llm_analyzer.py        # LLM-based finding analysis
    └── clustering.py          # Anomaly clustering

api/
├── server.py                  # FastAPI REST server
├── models.py                  # Pydantic models
└── job_queue.py               # Async job queue

plugins/
├── detectors/                 # Plugin detectors
├── reporters/                 # Plugin reporters
└── hooks/                     # Plugin hooks

tests/                         # 41 tests across 10 test files
```

### Security Features

- **Destructive blocklist**: `rm -rf`, `mkfs`, `dd if=`, fork bombs, reverse shells, SQL writes — hard-coded, non-bypassable
- **Immutable operator profiles**: Internal, Bounty, Gov — behavioral constraints enforced at code level
- **SSL verification**: On by default, `--insecure` flag for opt-out
- **Rate limiting**: Token-bucket algorithm (configurable max_rps)
- **WAF detection**: 50+ WAF signatures, auto-abort on detection
- **Thread safety**: `threading.Lock` on all shared state

### Test Coverage

| Module | Tests | Coverage |
|--------|-------|----------|
| classifier | 4 | Destructive patterns, file classification, content heuristics, stage detection |
| detector | 10 | 7 core + expanded signatures, headers, heuristics, false positives |
| diff | 4 | Identity, status change, null response, score range |
| profiles | 6 | All profiles, fallback, immutability |
| reasoning | 4 | LFI chains (Linux/Windows), SSTI, empty findings |
| mutation | 5 | Original, URL encoding, SQL, LFI, evasion levels |
| time_based | 2 | Payload structure and existence |
| auth | 3 | None, Bearer token, dataclass |

### Known Limitations

| Area | Limitation | Mitigation |
|------|-----------|------------|
| **WebSocket** | Only detects endpoints + sends test messages; no persistent connection fuzzing | Plugin system allows custom WS fuzzers |
| **gRPC** | No native gRPC reflection/probing | Protocol expansion via plugins |
| **AI/ML** | Requires external Ollama server + optional scikit-learn | Falls back gracefully when unavailable |
| **API mode** | In-memory job queue (not persistent) | Suitable for single-instance; add Redis for HA |
| **Auth** | No OAuth2 refresh flow, no SAML | Cookie jar + bearer token covers most enterprise cases |

### Docker

```bash
docker pull nullc0d30/hunterx:latest
docker run --rm -v $(pwd)/reports:/data nullc0d30/hunterx:latest -u http://target.com -o /data

# API mode
docker run --rm -p 8443:8443 nullc0d30/hunterx:latest api --port 8443
```

---

## License & Disclaimer

Proprietary — NullC0d3. For authorized security auditing and educational purposes only. Use responsibly and ethically.
