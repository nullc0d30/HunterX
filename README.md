# HunterX v4.0.1

[![CI](https://img.shields.io/github/actions/workflow/status/nullc0d30/HunterX/test.yml?branch=main&label=CI&logo=github)](https://github.com/nullc0d30/HunterX/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python)](https://www.python.org/)
[![Docker](https://img.shields.io/docker/pulls/nullc0d30/hunterx?logo=docker)](https://hub.docker.com/r/nullc0d30/hunterx)
[![Tests](https://img.shields.io/badge/tests-76%20passing-brightgreen)](https://github.com/nullc0d30/HunterX/actions)
[![Ruff](https://img.shields.io/badge/lint-ruff-brightgreen)](https://github.com/astral-sh/ruff)
[![Last Commit](https://img.shields.io/github/last-commit/nullc0d30/HunterX)](https://github.com/nullc0d30/HunterX/commits/main)
[![Stars](https://img.shields.io/github/stars/nullc0d30/HunterX?style=social)](https://github.com/nullc0d30/HunterX/stargazers)

**The AI-Assisted Vulnerability Hunter — Automated Decision Support for Offensive Operations**

HunterX is a production-grade Red Team orchestration framework by **Ahmed Awad (NullC0d3)**. It acts as a reasoning engine that observes, hypothesizes, probes, and verifies vulnerabilities using a strictly gated 4-stage pipeline with extreme operational safety, explainability, and stealth.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLI / API / Docker                     │
├─────────────────────────────────────────────────────────┤
│                    Orchestration Engine                   │
│         (4-Stage Pipeline: Observe → Hypothesize         │
│              → Probe → Verify)                           │
├──────────┬──────────┬──────────┬──────────┬──────────────┤
│  Session  │  Config  │ Profiles │  Auth    │   Plugins    │
│  Manager  │  System  │  Engine  │ Provider │   (Detect)   │
├──────────┼──────────┼──────────┼──────────┤    (Report)  │
│  WAF     │  Diff    │ Payload  │ OOB/Time│    (Hook)     │
│  Detector│  Engine  │ Manager  │ Based   │              │
├──────────┴──────────┼──────────┼──────────┴──────────────┤
│   Detection Engine   │   AI/ML   │   Protocol Handlers   │
│  (200+ signatures)   │  (Ollama) │  (WS, GraphQL)        │
├──────────────────────┴──────────┴──────────────────────┤
│              Reporter (MD, JSON, SARIF, HTML)            │
└─────────────────────────────────────────────────────────┘
```

---

## v4.0.1 Highlights

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
| **11** | **Apache 2.0 license** — fully open-source with DCO for contributions | Done |
| **12** | Docker 271MB (was 700MB), 76 tests (was 41), CI matrix (3.11/3.12/3.13) | Done |

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

## Full Project Audit (v4.0.1)

### Code Quality

| Metric | Value |
|--------|-------|
| **Total source files** | 38 Python files |
| **Lines of code** | ~5,200 (core) + ~800 (tests) + ~200 (plugins) |
| **Test count** | 76 pytest tests |
| **Test pass rate** | 100% |
| **Lint status** | ruff — 0 errors |
| **Python versions** | 3.11, 3.12, 3.13 |
| **License** | Apache 2.0 |
| **External dependencies** | 7 (requests 2.33.0, rich, dataclasses-json, pyyaml, jsonschema, websocket-client, beautifulsoup4) |
| **Optional dependencies** | lxml, fastapi, uvicorn, ollama, scikit-learn, numpy |

### Architecture

```
hunterx.py                     # CLI entry point
core/
├── engine.py                  # Orchestration engine
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

tests/                         # 76 tests across 14 test files
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
| config | 7 | Defaults, env overrides, user-agent lists |
| session | 6 | UA rotation, captcha, backoff calculation |
| engine | 10 | Init, dry run, fingerprint, diff, detector, classifier |
| api | 10 | ScanStatus, job queue, concurrent safety, graceful fallback |

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

## License

Copyright (c) 2026 **Ahmed Awad (NullC0d3)**.

Licensed under the **Apache License, Version 2.0** (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See [LICENSE](LICENSE) and [NOTICE](NOTICE) for full details.

### Commercial Use

HunterX is free and open-source software. If your organization uses it commercially, please consider supporting the project via [GitHub Sponsors](https://github.com/sponsors/nullc0d30).

### Attribution

**Author:** Ahmed Awad (NullC0d3)
**Repository:** [https://github.com/nullc0d30/HunterX](https://github.com/nullc0d30/HunterX)
**License:** [Apache 2.0](LICENSE)

### Legal Notice

HunterX is provided for **authorized security assessments, defensive security research, professional penetration testing, red team exercises, and educational use only**. Users must obtain explicit written permission from the owner of any target system before scanning or testing. Unauthorized access to computer systems is illegal and unethical.

The developer (Ahmed Awad / NullC0d3) is **NOT responsible** for any illegal use, unauthorized attacks, misuse, abuse, damage caused by third parties, or violation of local laws. **Users are solely responsible** for ensuring compliance with all applicable local, national, and international laws.

### Reporting Issues

Found a bug or have a feature request? Please open an issue at:
[https://github.com/nullc0d30/HunterX/issues](https://github.com/nullc0d30/HunterX/issues)

For security vulnerabilities in the tool itself, please use the private vulnerability reporting mechanism on GitHub.

---

---

## Community

HunterX is more than a tool — it's a community of security researchers, Red Team operators, bug bounty hunters, and developers working together to make security assessments safer, smarter, and more accessible. Licensed under **Apache 2.0**, HunterX is fully open-source.

### Join Us

| Activity | How to Participate |
|----------|-------------------|
| ⭐ **Star the repo** | Show your support and help others discover HunterX |
| 🍴 **Fork the repo** | Create your own version, experiment, contribute |
| 🐛 **Report bugs** | File detailed reports to help us improve |
| 💡 **Suggest ideas** | Propose features that make HunterX better |
| 🔧 **Submit PRs** | Fix bugs, add features, optimize code |
| 📖 **Improve docs** | Fix typos, add examples, write guides |
| ❤️ **Help others** | Answer questions in issues and discussions |
| 🗣 **Spread the word** | Share HunterX with your network |
| 🌐 **Translate** | Help make HunterX accessible globally |

### Why Star the Project?

- **Visibility** — More stars = more contributors = faster development
- **Validation** — Stars signal quality and trust to new users
- **Motivation** — It tells the maintainer that the work matters
- **Discovery** — Helps others find HunterX through GitHub trending

### Why Fork the Project?

- **Learn** — Study the architecture of a production-grade security tool
- **Customize** — Adapt HunterX for your organization's specific needs
- **Experiment** — Test new detection techniques, plugins, or protocols
- **Contribute** — Use your fork as a staging ground for pull requests
- **Innovate** — Build on top of HunterX for research, education, or commercial use (per Apache 2.0)

### A Personal Invitation

> *HunterX was built with a simple belief: security tools should be safe, explainable, and community-owned. Whether you're a seasoned Red Team operator, a security researcher pushing the boundaries of AI-assisted testing, or a student taking your first steps into cybersecurity — there's a place for you here.*
>
> *Star the repo. Fork it. Break it. Fix it. Make it better. Share what you learn. The only bad contribution is the one not made.*
>
> *— Ahmed Awad (NullC0d3)*

---

## Contributing

We welcome contributions of all kinds — from fixing typos to building new modules. HunterX follows standard open-source collaboration practices under the **Apache 2.0** license.

### Quick Start

```bash
# Fork, then clone
git clone https://github.com/YOUR_USERNAME/HunterX.git
cd HunterX

# Set up environment
pip install -r requirements.txt

# Create a branch
git checkout -b feat/your-feature

# Make changes, then test
python -m pytest tests/ -v
ruff check core/ hunterx.py api/ plugins/ tests/ --ignore=E501

# Commit and push
git commit -m "feat(area): description"
git push origin feat/your-feature
```

### Resources

- **[CONTRIBUTING.md](CONTRIBUTING.md)** — Full contribution guide
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** — Community standards
- **[ROADMAP.md](ROADMAP.md)** — Planned features and direction
- **[Issue Templates](.github/ISSUE_TEMPLATE/)** — Structured issue reporting
- **[PR Template](.github/PULL_REQUEST_TEMPLATE.md)** — Pull request checklist

### Good First Issues

New to the project? Look for issues labeled [`good first issue`](https://github.com/nullc0d30/HunterX/labels/good%20first%20issue) — they are curated to be approachable for first-time contributors.

---

## Roadmap

| Version | Focus | Target |
|---------|-------|--------|
| **v4.0.1** ✅ | Apache 2.0, Docker optimization, security fixes, 76 tests | July 2026 |
| **v4.1** | gRPC, OAuth2, Redis queue, TUI, i18n | Q3 2026 |
| **v4.5** | RBAC, SIEM, Scheduled scans, Compliance reporting | Q4 2026 |
| **v5.0** | Autonomous agent, Cloud scanning, SDK | H1 2027 |

See the full [ROADMAP.md](ROADMAP.md) for details.

---

## Support

| Resource | Purpose | Link |
|----------|---------|------|
| Documentation | Installation, usage, configuration | [README.md](README.md) |
| Contributing Guide | How to contribute | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Security Policy | Vulnerability disclosure | [SECURITY.md](SECURITY.md) |
| Discussions | Questions, ideas, community help | [GitHub Discussions](https://github.com/nullc0d30/HunterX/discussions) |
| Issues | Bug reports, feature requests | [GitHub Issues](https://github.com/nullc0d30/HunterX/issues) |
| Docker Hub | Container images | [nullc0d30/hunterx](https://hub.docker.com/r/nullc0d30/hunterx) |

---

## Security

Security is at the core of HunterX — both the tool's purpose and its development process.

### For Users of HunterX

- **Authorized use only** — Always obtain written permission before scanning
- **Latest version** — Keep HunterX updated for the latest features and fixes
- **Container isolation** — Run in Docker for environment control
- **Report responsibly** — Disclose findings through proper channels

### For Contributors to HunterX

We take the security of the tool itself seriously. If you discover a vulnerability in HunterX:

1. **Do NOT** open a public issue
2. Report via **GitHub Private Vulnerability Reporting** (Security tab)
3. Follow our [responsible disclosure policy](SECURITY.md)

Expected response time: **Within 72 hours**

---

## Responsible Disclosure

HunterX follows a **coordinated disclosure** model for vulnerabilities found in the tool itself:

1. **Private report** — Reporter submits vulnerability details privately
2. **Acknowledgment** — Maintainers respond within 72 hours
3. **Assessment** — Vulnerability is triaged and prioritized
4. **Fix development** — Patch is developed and tested
5. **Release** — Fixed version is released to all channels
6. **Disclosure** — Advisory published with reporter credit (opt-in)

---

## Credits

### Author & Maintainer

- **Ahmed Awad (NullC0d3)** — Creator, architect, and lead maintainer
  - GitHub: [@nullc0d30](https://github.com/nullc0d30)

### How to Get Credit

Contributors are recognized in:
- Release notes and changelogs
- GitHub Release announcements
- The project's README (significant contributions)
- The citation file ([CITATION.cff](CITATION.cff)) for academic credit

---

## Citation

If you use HunterX in academic research, please cite:

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

See [CITATION.cff](CITATION.cff) for the full citation metadata.

---

## Acknowledgements

HunterX stands on the shoulders of the broader security community. Special thanks to:

- **OWASP** — For their invaluable security testing methodologies
- **PayloadsAllTheThings** — For comprehensive payload collections
- **The Python community** — For robust and secure libraries
- **FastAPI, Ruff, Pytest** — For excellent development tooling
- **All contributors and stargazers** — For believing in this project

---

## Star History

Liked HunterX? **Give it a star ⭐** on GitHub — it helps the project grow and reach more security professionals worldwide.

[![Star History Chart](https://api.star-history.com/svg?repos=nullc0d30/HunterX&type=Date)](https://star-history.com/#nullc0d30/HunterX&Date)

---

*HunterX — Safe, smart, community-driven security assessment. Apache 2.0 licensed.*
