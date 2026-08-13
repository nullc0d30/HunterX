<div align="center">

<img src="https://raw.githubusercontent.com/nullc0d30/HunterX/main/docs/assets/images/logof.png" alt="HunterX official logo" width="220" height="auto">

# HunterX

## AI-Assisted Offensive Security Engine

### Discover. Validate. Prove. Report.

HunterX is not merely a vulnerability scanner. It is an open-source,
AI-assisted **offensive security engine** for planning and running authorized
security-assessment missions. It combines **reconnaissance**, **security-tool
orchestration**, **AI-assisted reasoning**, **hypothesis-driven investigation**,
**vulnerability validation**, **evidence collection**, **proof / PoC
engineering**, **replay / reproducibility**, **correlation**, **impact
assessment** and **professional reporting** into a single workflow.

[![GitHub Release](https://img.shields.io/github/v/release/nullc0d30/HunterX?style=flat-square&logo=github)](https://github.com/nullc0d30/HunterX/releases)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0)
[![Tests](https://img.shields.io/github/actions/workflow/status/nullc0d30/HunterX/test.yml?style=flat-square&label=tests)](https://github.com/nullc0d30/HunterX/actions)
[![Docker](https://img.shields.io/badge/docker-multi--stage-2496ED?style=flat-square&logo=docker)](https://hub.docker.com/r/nullc0d30/hunterx)
[![PyPI](https://img.shields.io/pypi/v/hunterxsec?style=flat-square&logo=pypi&label=pypi)](https://pypi.org/project/hunterxsec/)
[![OWASP Community](https://img.shields.io/badge/OWASP%20Community-listed-green?style=flat-square&logo=owasp)](https://owasp.org/www-community/Vulnerability_Scanning_Tools)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat-square)](https://github.com/nullc0d30/HunterX)

**Less noise. More verified findings.**

</div>

<p align="center">
  <img src="https://raw.githubusercontent.com/nullc0d30/HunterX/main/docs/assets/images/des.png" alt="HunterX v7 capability overview showing AI-assisted reasoning, vulnerability validation, verified findings, tool integrations, and security workflow." width="100%">
</p>

> **The core message.** HunterX does not stop at finding a *possible*
> vulnerability. It is built to **investigate the hypothesis, validate the
> behavior, prove the finding, reproduce the evidence, assess the impact, and
> turn the result into a report-ready security finding.**

```
Vulnerability
+ Evidence
+ Reproducibility
+ Proof / PoC
+ Impact
================
Validated Finding
```

> **Responsible use.** HunterX is an authorized cybersecurity testing and
> research platform. You are responsible for obtaining appropriate
> authorization before testing any system. The author is not responsible for
> misuse, unauthorized access, illegal activity, or damage caused by the
> software. See [Responsible Use](#responsible-use) and
> [SECURITY.md](SECURITY.md).

---

## A Scanner Finds a Possibility. HunterX Builds the Case.

A traditional scanner reports a candidate and stops:

```
Traditional Scanner

"Possible SQL Injection"
          ↓
       Finding?
```

HunterX carries the candidate through the full investigation:

```
Candidate
   ↓
Affected Endpoint
   ↓
Parameter
   ↓
Observed Behavior
   ↓
Hypothesis
   ↓
Verification
   ↓
Evidence
   ↓
Minimal Reproducible PoC
   ↓
PoC Validation
   ↓
Impact
   ↓
Report-Ready Finding
```

`"Possible SQL Injection"` is only a **hypothesis**. HunterX is designed to
investigate, validate, prove, reproduce, correlate and report it — not to
surface it as a verdict. Every claim HunterX makes is backed by observations,
evidence, validation, proof, replay records, impact and provenance. A finding
is only `REPORT_READY` when the reportability contract is satisfied.

---

## From Detection to Validated Finding

A vulnerability **detection is not a validated finding**. HunterX drives each
candidate through a lifecycle:

```
DETECTED → SUSPECTED → VALIDATING → VALIDATED → PROVEN → CONFIRMED → REPORT_READY
                                            ↘ FALSE_POSITIVE
                                            ↘ INCONCLUSIVE
```

- `DETECTED` / `SUSPECTED` — a candidate from tool output or reasoning. Not yet
  validated.
- `VALIDATING` / `VALIDATED` — behavior is tested and compared against the
  hypothesis.
- `PROVEN` — requires a valid, reproducible proof.
- `CONFIRMED` — requires the vulnerability-specific proof contract to permit
  confirmation and the confidence requirements to be met.
- `REPORT_READY` — requires evidence, proof, a reproducible PoC, impact,
  confidence, scope, timestamp and provenance.
- `FALSE_POSITIVE` — requires evidence that the original hypothesis was
  incorrect.
- `INCONCLUSIVE` — the outcome could not be determined (target changed,
  preconditions changed, WAF behavior changed, network instability, failed
  tool run or insufficient evidence).

A PoC that fails is **never automatically a false positive**. The engine
distinguishes `FALSE_POSITIVE` from `INCONCLUSIVE` deliberately.

---

## How HunterX Works

HunterX orchestrates the complete assessment workflow rather than attempting to
replace the security-tool ecosystem:

```
DISCOVER
    ↓
FINGERPRINT
    ↓
REASON
    ↓
HYPOTHESIZE
    ↓
PROBE
    ↓
VERIFY
    ↓
PROVE
    ↓
POC
    ↓
REPLAY
    ↓
CORRELATE
    ↓
REPORT
```

| Phase | Purpose |
|---|---|
| **DISCOVER** | Surface the attack surface — assets, services, endpoints. |
| **FINGERPRINT** | Identify technologies, versions and exposure. |
| **REASON** | Generate and prioritize hypotheses with AI-assisted reasoning. |
| **HYPOTHESIZE** | Turn candidates into testable vulnerability hypotheses. |
| **PROBE** | Execute targeted checks and tool runs against each hypothesis. |
| **VERIFY** | Compare observed behavior against expected behavior. |
| **PROVE** | Require evidence and reproducible proof before a finding advances. |
| **POC** | Engineer minimal, safe, replayable PoCs. |
| **REPLAY** | Reproduce the proof deterministically — more than once. |
| **CORRELATE** | Connect evidence, findings and attack paths across tools and missions. |
| **REPORT** | Produce professional, evidence-traced reports. |

HunterX **orchestrates** open-source security tools: it executes them with
structured contracts, parses and normalizes their output into canonical
observations, correlates results, reasons over hypotheses, validates with
evidence, engineers and replays proofs/PoCs, and produces reports. It is built
to work with the ecosystem, not to own every security capability itself.

---

## What HunterX Brings Together

HunterX v7.0.0 (2026-08-11) is the production-ready v7 release. It assembles
these capability areas into one platform:

### Intelligence

- Reconnaissance
- Asset discovery
- Fingerprinting
- Target intelligence
- Cloud / SaaS attack-surface intelligence

### Reasoning

- AI-assisted reasoning
- Hypothesis generation
- Adaptive mission planning
- Attack-path analysis
- Explainable next-best-action selection

### Validation

- Vulnerability validation
- Evidence collection
- Proof contracts
- PoC engineering
- Replay / reproducibility
- Impact assessment

### Correlation

- Cross-tool correlation
- Knowledge graph
- Evidence chains
- Topology
- Mission history

### Reporting

- Findings & evidence bundles
- Remediation & retesting
- Markdown · HTML · JSON · SARIF 2.1 · PDF · evidence packages

**Platform capabilities** — autonomous mission orchestration and adaptive
planning (`hunterx mission`, `hunterx hunt`); a Tool Integration SDK and
tool-intelligence platform with a 92-tool arsenal manifest; persistent target
intelligence (TIDB) with Alembic migrations, events, audit and versioning;
topology and a typed event bus; knowledge-graph correlation; the Vulnerability
Proof & PoC Validation Engine; professional multi-format reporting; security
hardening (scope and authorization guards, sandboxing, evidence-gated
confidence, secret masking, hardened XML parsing); an idempotent `install.sh`
installer, Docker image and PyPI packaging; CI/CD pipelines; and comprehensive
v7 documentation.

---

# The Proof Engine

HunterX treats **proof as part of vulnerability validation**. The proof engine
transforms a validated hypothesis into a report-ready finding:

```
HYPOTHESIS
    ↓
PROOF CONTRACT
    ↓
REQUIRED EVIDENCE
    ↓
MINIMAL PROOF STRATEGY
    ↓
PROOF CONSTRUCTION
    ↓
SAFETY VALIDATION
    ↓
SCOPE VALIDATION
    ↓
EXECUTION
    ↓
REPLAY
    ↓
EVIDENCE EVALUATION
    ↓
IMPACT
    ↓
CONFIDENCE
    ↓
VALIDATED FINDING
    ↓
REPRODUCTION PACKAGE
    ↓
REPORT
```

Two distinctions are fundamental:

```
GENERATED ≠ VALIDATED
EXECUTED ≠ VALIDATED
```

Generating a PoC proves nothing. Executing it once proves nothing. A finding is
only `PROVEN` / `CONFIRMED` / `REPORT_READY` when its evidence, proof and
reproducibility requirements are actually satisfied.

- **Proof contracts** — every supported vulnerability class has a deterministic
  contract defining preconditions, allowed and forbidden actions, required
  evidence, expected behavior, replay and impact requirements. Classes include
  SQL/NoSQL injection, XSS, SSRF, path traversal/LFI, IDOR, authentication,
  authorization, SSTI, XXE, command-injection indicators, cloud exposure and
  `UNKNOWN_BEHAVIOR`.
- **Minimal, safe proofs** — PoCs are structured artifacts (request templates,
  differential tests, configuration snapshots), never arbitrary executable
  scripts. Inputs are bounded, forbidden markers are refused, secrets are
  redacted, and every PoC is immutable with lineage.
- **Replay & reproducibility** — proofs are replayed deterministically with a
  `SUCCESS` / `FAILED` / `INCONCLUSIVE` / `BLOCKED` verdict. `REPRODUCIBLE`
  requires repeated successful replays — never a single run. A single
  "executed once" is never "reproducible".
- **Evidence-driven impact & confidence** — impact is classified strictly from
  captured evidence, never inferred merely from the vulnerability class.
  Confidence is a versioned, weighted policy over named factors — never a
  universal percentage. `CONFIRMED` can never be reached unless the proof
  contract permits confirmation.
- **Novel / unknown behavior** — unknown behaviors follow a hypothesis-driven
  loop (`Unknown Behavior → Hypothesis → Experiment → Unexpected Result → New
  Hypothesis → Minimal Proof → Validated Finding`) and remain candidates until
  sufficient evidence exists. HunterX supports hypothesis-driven investigation
  of unknown or application-specific behaviors; it does not claim guaranteed
  autonomous discovery of zero-days.
- **RCE, responsibly** — where applicable, proof emphasizes minimal-impact
  demonstration, evidence of execution and reproducibility — not destructive
  commands.

The engine is **not a weaponization engine**. Data destruction, persistence,
credential dumping, reverse shells, lateral movement, DoS, mass data extraction
and unrestricted database extraction are never scheduled. Proof means
demonstrating the vulnerability with the minimum necessary interaction and
impact.

---

## What Can HunterX Investigate?

HunterX supports vulnerability discovery, validation and proof across a broad
set of classes, as supported by its proof-contract registry:

| | | |
|---|---|---|
| SQL Injection | NoSQL Injection | XSS |
| SSRF | Path Traversal / LFI | RCE / Command Injection Indicators |
| IDOR / BOLA | SSTI | XXE |
| Authentication | Authorization | API |
| GraphQL | Open Redirect | CORS |
| Sensitive Information Exposure | Security Misconfiguration | Known Vulnerable Components |
| Dependency Vulnerabilities | Cloud Exposure | `UNKNOWN_BEHAVIOR` |

Validation depth is defined per class by the proof-contract registry — not every
class has identical validation depth, and HunterX never claims otherwise. See
[PoC & Validation](docs/poc-validation.md) for the full contract model.

---

## Quick Start

```
INSTALL → HUNT → INSPECT → VALIDATE → REPORT
```

HunterX v7 organizes work as **missions**. Start with an authorized target:

```bash
# 1. INSTALL — Python 3.11+ on Linux, macOS or Windows
pip install hunterxsec
# or from source:  git clone https://github.com/nullc0d30/HunterX.git && cd HunterX
#                  python -m pip install -e ".[api,db,dev]"
# or installer:   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash

# 2. HUNT — plan and start a full-spectrum hunt mission
hunterx hunt full_security_assessment https://example.com

# 3. INSPECT — track the mission and inspect the toolchain
hunterx hunt status <mission_id>
hunterx hunt surface <mission_id>
hunterx tools list
hunterx tools capabilities
hunterx tools health

# 4. VALIDATE — work findings, PoCs and proof replay
hunterx finding list <mission_id>
hunterx finding poc <finding_id>       # PoC engineering
hunterx finding proof <finding_id>     # proof state
hunterx finding replay <finding_id>    # proof replay

# 5. REPORT — generate and export professional reports
hunterx report generate <finding_id>
hunterx report export <report_id> markdown
```

Verify your install:

```bash
hunterx version     # HunterX v7.0.0
hunterx help        # command list
hunterx platform    # platform composition
hunterx config      # resolved configuration
```

Missions persist to the configured database (SQLite by default), so
`hunterx mission create <objective> <target>` followed by
`hunterx mission start <mission_id>` works across CLI invocations.

See [Quickstart](docs/quickstart.md) and the full
[CLI Reference](docs/cli/index.md) for complete usage.

---

## Persistent Target Intelligence

HunterX does not treat every scan as an isolated command. It maintains
**structured target intelligence** that persists and correlates across runs:

```
assets / targets → observations → findings → evidence
      ↘ history → relationships / topology → mission state
      ↘ cloud intelligence → correlation → tool results
```

- **assets / targets** — the surface under assessment
- **observations** — canonical normalized results from every tool run
- **findings** — validated results with evidence and proof
- **evidence** — provenance-backed evidence records
- **history** — target snapshots, diffs and change detection
- **relationships / topology** — how assets, services and cloud resources relate
- **cloud intelligence** — cloud/SaaS attack-surface intelligence
- **correlation** — cross-tool evidence chains
- **mission state** — checkpoint/resume and campaign state
- **tool results** — structured execution records

---

## Cloud & SaaS Attack-Surface Intelligence

HunterX v7 includes evidence-backed **Cloud & SaaS Attack-Surface
Intelligence**. Where supported, provider coverage includes **AWS, Azure, GCP,
OCI, Cloudflare, DigitalOcean, Akamai, Fastly, Vercel, Netlify, Heroku, Render,
Fly.io, Supabase, Firebase, Kubernetes and Docker**.

It provides provider detection, cloud resource intelligence, exposure
classification, environment classification, topology, account/region/resource
relationships, SaaS detection, cloud evidence and correlation — built from
passive, static evidence (DNS, TLS, HTTP headers, HTML/JS, OpenAPI,
documentation) for authorized targets. It **never authenticates to cloud
accounts, never accesses cloud resources and never retrieves secrets.**

---

## Knowledge Graph & Cross-Tool Correlation

HunterX correlates results across tools and missions into a knowledge graph of
entities and relationships:

```
Assets
  ↕
Services
  ↕
Observations
  ↕
Findings
  ↕
Evidence
  ↕
Proofs
  ↕
Attack Paths
```

This enables cross-scan correlation, attack-path analysis and context-aware
reasoning across missions.

---

## From Finding to Professional Report

The workflow does not end at detection:

```
Finding
   ↓
Evidence
   ↓
Verification
   ↓
PoC
   ↓
Reproduction
   ↓
Impact
   ↓
Remediation
   ↓
Report
```

HunterX turns validated findings into structured, professional reports with
verified export formats:

```
JSON  → machine-parsable
Markdown → human-readable
HTML  → visual dashboard
SARIF 2.1 → VS Code / GitHub CodeQL integration
PDF   → document export
Evidence Package → bundled evidence (ZIP)
```

Reports include finding, asset, endpoint, parameter, evidence, verification,
PoC, reproduction, impact, confidence, relationships, risk/context, and
remediation/recommendations where supported. Every statement traces to
observation, evidence, validation, proof, impact, tool result, target
intelligence or explicit analyst reasoning.

---

## Installation

Requirements: **Python 3.11+** on Linux, macOS or Windows.

```bash
# Installer script (Linux/macOS)
curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash

# From PyPI — https://pypi.org/project/hunterxsec/
python -m pip install hunterxsec

# Or from source
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
python -m pip install -e ".[api,db,dev]"
```

> **Name note.** The GitHub repository
> [nullc0d30/HunterX](https://github.com/nullc0d30/HunterX) is the canonical
> home of HunterX, created and maintained by Ahmed Awad (AKA NullC0d3). The
> HunterX v7 distribution is published to [PyPI](https://pypi.org/project/hunterxsec/)
> as `hunterxsec`; the plain `hunterx` name on PyPI belongs to a different,
> unrelated project. The import package and CLI command are `hunterx` either
> way.

Verify your install with `hunterx version` (see [Quick Start](#quick-start)).

See [Installation](docs/installation/index.md) for details, including database
initialization (`alembic upgrade head`) and Docker.

## CLI Reference

HunterX v7 ships a single `hunterx` command with capability groups:

| Area | Commands |
|---|---|
| Missions | `hunterx mission create/start/status/pause/resume/cancel/finalize`, `hunterx hunt ...` |
| Planning | `hunterx mission plan/replan/paths/explain` |
| Findings | `hunterx finding create/list/show/validate/poc/proof/replay/explain` |
| Reports | `hunterx report list/generate/export/sarif/remediation/retest` |
| Targets | `hunterx target memory/snapshot/diff/changes/history/coverage/revalidate` |
| Campaigns | `hunterx campaign list/show/intelligence` |
| Toolchain | `hunterx tools list/show/contract/execute/parse/normalize/chain/recommend` |

See [CLI Reference](docs/cli/index.md) for the full command reference.

## REST API

The v7 REST API is a FastAPI application (`hunterx.api.app:create_app`). Install
from source with the `api` extra and run:

```bash
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
python -m pip install -e ".[api]"
uvicorn hunterx.api.app:create_app --host 127.0.0.1 --port 8080
```

API-key authentication is opt-in (admin/read-only roles). See
[Documentation Hub](docs/documentation.md).

## Docker

Official images are published on
[Docker Hub](https://hub.docker.com/r/nullc0d30/hunterx) as
`nullc0d30/hunterx` for Linux (amd64 / arm64). Tags follow the version
(`7`, `7.0`, `7.0.0`) plus `latest` and `stable`.

> 🚀 **1.7K+ Docker image pulls and counting.**

### Pull from Docker Hub

```bash
docker pull nullc0d30/hunterx:latest
```

### Run the CLI

```bash
# Show the version
docker run --rm nullc0d30/hunterx:latest version

# Show help
docker run --rm nullc0d30/hunterx:latest help

# Interactive shell
docker run -it --rm --entrypoint sh nullc0d30/hunterx:latest
```

### Run the REST API

The image ships with the `api` extras. Start the FastAPI server and point a
browser at <http://localhost:8080/health>:

```bash
docker run -d --name hunterx-api -p 8080:8080 \
  --entrypoint uvicorn nullc0d30/hunterx:latest \
  --factory hunterx.api.app:create_app --host 0.0.0.0 --port 8080
```

Configuration is passed with `HUNTERX_*` environment variables (for example
`HUNTERX_API_PORT` or `HUNTERX_DATABASE_URL`).

### Docker Compose

`docker-compose.yml` ships a `hunterx-api` service (FastAPI) and a `hunterx`
CLI service backed by the `nullc0d30/hunterx:latest` image:

```bash
docker compose up -d hunterx-api
```

The container runs as a non-root user, exposes `8080`, and keeps persistent
state under the named volume. See
[Release Guide](docs/v7-release-guide.md) for build and publishing details.

---

# Tool Ecosystem

> HunterX is designed to orchestrate the security tooling ecosystem rather than
> replace it.

HunterX integrates with, executes, parses, normalizes and correlates output
from open-source security tools where the actual v7 implementation supports
them. Integration status per tool is tracked in the
[toolchain manifest](capabilities/full-toolchain-intelligence.json) and on the
[Tool Ecosystem](docs/tool-ecosystem.md) page. Status labels:

- **Integrated (fully-supported)** — structured execution, parser and
  normalizer.
- **Integrated (partial-support)** — parser/normalizer or adapter with
  documented limitations.
- **Integrated (execution-only)** — structured execution with a guarded adapter
  (never arbitrary subprocess).
- **Planned / Resource** — registered as a knowledge resource or known tool;
  not claimed as direct execution.

**Categorized summary** — 92 registered tools: recon & asset discovery (13),
network & port scanning (7), HTTP, crawling & discovery (10), fuzzing & content
discovery (5), parameter & endpoint discovery (6), vulnerability detection &
validation (17), source, code & secret analysis (5), proxy & web security (2),
exploitation & security research (3), knowledge & payload resources (3), cloud,
container & supply chain (7), enterprise / Active Directory (9), and DNS, API &
proof (5).

### Recon / Asset Discovery

| Tool | Role in HunterX | Status |
|---|---|---|
| [Amass](https://github.com/owasp-amass/amass) | subdomain/ASN/org enumeration, asset discovery | Integrated (fully-supported) |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | subdomain enumeration | Integrated (fully-supported) |
| [Assetfinder](https://github.com/tomnomnom/assetfinder) | subdomain enumeration | Integrated (fully-supported) |
| [Findomain](https://github.com/Findomain/Findomain) | subdomain/certificate enumeration | Integrated (fully-supported) |
| [theHarvester](https://github.com/laramies/theHarvester) | OSINT, email/subdomain enumeration | Integrated (fully-supported) |
| [BBOT](https://github.com/blacklanternsecurity/bbot) | attack-surface discovery | Integrated (fully-supported) |
| [DNSx](https://github.com/projectdiscovery/dnsx) | DNS resolution, records, wildcards | Integrated (fully-supported) |
| [MassDNS](https://github.com/blechschmidt/massdns) | high-performance DNS resolution | Integrated (partial-support) |
| [Shuffledns](https://github.com/projectdiscovery/shuffledns) | massdns wrapper for brute-force | Integrated (partial-support) |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | OSINT automation | Integrated (partial-support) |
| [DNSrecon](https://github.com/darkoperator/dnsrecon) | DNS records/brute-force | Planned / Resource |
| [Crobat](https://github.com/Cgboal/SonarSearch) | subdomain enumeration | Integrated (partial-support) |
| [crt.sh](https://crt.sh/) | certificate transparency | Integrated (partial-support) |

### Network / Port Scanning

| Tool | Role in HunterX | Status |
|---|---|---|
| [Naabu](https://github.com/projectdiscovery/naabu) | port discovery | Integrated (fully-supported) |
| [Nmap](https://nmap.org/) | port/service/version/OS discovery | Integrated (fully-supported) |
| [Masscan](https://github.com/robertdavidgraham/masscan) | fast port scanning | Integrated (fully-supported) |
| [RustScan](https://github.com/bee-san/RustScan) | fast port scanning | Integrated (partial-support) |
| Unicornscan | port discovery | Planned / Resource |
| [fping](https://fping.org/) | host discovery | Planned / Resource |
| [arp-scan](https://github.com/royhills/arp-scan) | host discovery | Planned / Resource |

### HTTP / Crawling / Discovery

| Tool | Role in HunterX | Status |
|---|---|---|
| [HTTPx](https://github.com/projectdiscovery/httpx) | HTTP probing, tech detection | Integrated (fully-supported) |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | technology detection | Integrated (fully-supported) |
| [Katana](https://github.com/projectdiscovery/katana) | crawling, URL/endpoint discovery | Integrated (fully-supported) |
| [Gospider](https://github.com/jaeles-project/gospider) | crawling, JS discovery | Integrated (partial-support) |
| [Hakrawler](https://github.com/hakluke/hakrawler) | crawling | Integrated (partial-support) |
| [GAU](https://github.com/lc/gau) | historical URL discovery | Integrated (partial-support) |
| [Waybackurls](https://github.com/tomnomnom/waybackurls) | historical URL discovery | Integrated (partial-support) |
| URLFinder | historical URL discovery | Integrated (partial-support) |
| [gauplus](https://github.com/bp0lr/gauplus) | historical URL discovery | Integrated (partial-support) |
| [Wafw00f](https://github.com/EnableSecurity/wafw00f) | WAF detection | Planned / Resource |

### Fuzzing / Content Discovery

| Tool | Role in HunterX | Status |
|---|---|---|
| [FFUF](https://github.com/ffuf/ffuf) | content/directory/vhost discovery | Integrated (fully-supported) |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | content discovery | Integrated (partial-support) |
| [Gobuster](https://github.com/OJ/gobuster) | directory/vhost enumeration | Integrated (partial-support) |
| [Dirsearch](https://github.com/maurosoria/dirsearch) | directory enumeration | Integrated (partial-support) |
| [Kiterunner](https://github.com/assetnote/kiterunner) | API/content discovery | Integrated (partial-support) |

### Parameter / Endpoint Discovery

| Tool | Role in HunterX | Status |
|---|---|---|
| [Arjun](https://github.com/s0md3v/Arjun) | HTTP parameter discovery | Integrated (partial-support) |
| [ParamSpider](https://github.com/devanshbatham/ParamSpider) | parameter discovery | Integrated (partial-support) |
| [LinkFinder](https://github.com/GerbenJavado/LinkFinder) | JS endpoint extraction | Integrated (partial-support) |
| [SecretFinder](https://github.com/m4ll0k/SecretFinder) | JS secret indicators | Integrated (partial-support) |
| [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder) | JS endpoint extraction | Integrated (partial-support) |
| [JSluice](https://github.com/BishopFox/jsluice) | JS analysis, secrets, source maps | Integrated (partial-support) |

### Vulnerability Detection / Validation

| Tool | Role in HunterX | Status |
|---|---|---|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | template-based scanning | Integrated (fully-supported) |
| [Dalfox](https://github.com/hahwul/dalfox) | XSS discovery/validation | Integrated (partial-support) |
| [XSStrike](https://github.com/s0md3v/XSStrike) | XSS analysis | Integrated (partial-support) |
| [SQLmap](https://github.com/sqlmapproject/sqlmap) | SQL injection detection/validation | Integrated (partial-support) |
| [Ghauri](https://github.com/r0oth3x49/ghauri) | SQL injection detection/validation | Integrated (partial-support) |
| [Commix](https://github.com/commixproject/commix) | command injection | Integrated (partial-support) |
| [Interactsh](https://github.com/projectdiscovery/interactsh) | OOB callbacks | Integrated (partial-support) |
| [Tplmap](https://github.com/epinna/tplmap) | SSTI detection | Integrated (partial-support) |
| [SSTImap](https://github.com/vladris/sstimap) | SSTI detection/validation | Integrated (partial-support) |
| [XXEinjector](https://github.com/enjoiz/XXEinjector) | XXE detection/validation | Integrated (partial-support) |
| [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) | GraphQL analysis | Integrated (partial-support) |
| [InQL](https://github.com/doyensec/inql) | GraphQL introspection | Integrated (partial-support) |
| [OpenVAS / Greenbone](https://github.com/greenbone/openvas-scanner) | vulnerability scanning | Planned / Resource |
| [Wapiti](https://github.com/wapiti-scanner/wapiti) | web vulnerability scanner | Integrated (partial-support) |
| [Nikto](https://github.com/sullo/nikto) | web server scanning | Integrated (partial-support) |
| [testssl.sh](https://github.com/drwetter/testssl.sh) | TLS analysis | Planned / Resource |
| [SSLScan](https://github.com/rbsec/sslscan) | TLS analysis | Planned / Resource |

### Source / Code / Secret Analysis

| Tool | Role in HunterX | Status |
|---|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | secret scanning | Integrated (fully-supported) |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | secret scanning | Integrated (partial-support) |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | secret scanning | Integrated (partial-support) |
| [Semgrep](https://github.com/semgrep/semgrep) | SAST | Integrated (partial-support) |
| [CodeQL CLI](https://github.com/github/codeql-cli-binaries) | SAST | Planned / Resource |

### Proxy / Web Security

| Tool | Role in HunterX | Status |
|---|---|---|
| [OWASP ZAP](https://github.com/zaproxy/zaproxy) | proxy, active testing | Integrated (partial-support) |
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) | HTTP interception, traffic capture | Integrated (partial-support) |

### Exploitation / Security Research

| Tool | Role in HunterX | Status |
|---|---|---|
| [Metasploit](https://github.com/rapid7/metasploit-framework) | exploit validation (execution-only) | Integrated (execution-only) |
| [SearchSploit](https://gitlab.com/exploit-database/exploitdb) | exploit research | Integrated (partial-support) |
| [ExploitDB](https://gitlab.com/exploit-database/exploitdb) | exploit research | Integrated (partial-support) |

### Knowledge / Payload Resources

| Tool | Role in HunterX | Status |
|---|---|---|
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | payload knowledge base | Integrated (partial-support) |
| [SecLists](https://github.com/danielmiessler/SecLists) | wordlists | Integrated (partial-support) |
| [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) | attack/response dictionaries | Integrated (partial-support) |

### Cloud / Container / Supply Chain

| Tool | Role in HunterX | Status |
|---|---|---|
| [Prowler](https://github.com/prowler-cloud/prowler) | cloud security audit | Integrated (partial-support) |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | cloud audit | Planned / Resource |
| [Trivy](https://github.com/aquasecurity/trivy) | container/image scanning | Integrated (partial-support) |
| [Syft](https://github.com/anchore/syft) | SBOM generation | Integrated (partial-support) |
| [Grype](https://github.com/anchore/grype) | container CVE analysis | Integrated (partial-support) |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | Kubernetes security | Planned / Resource |
| [OSV-Scanner](https://github.com/google/osv-scanner) | dependency scanning | Integrated (partial-support) |

### Enterprise / Active Directory

| Tool | Role in HunterX | Status |
|---|---|---|
| [NetExec](https://github.com/Pennyw0rth/NetExec) | SMB/AD enumeration | Planned / Resource |
| [Impacket](https://github.com/fortra/impacket) | SMB/Kerberos enumeration | Planned / Resource |
| [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) | SMB/AD enumeration | Planned / Resource |
| [ldapsearch](https://www.openldap.org/) | LDAP enumeration | Planned / Resource |
| [rpcclient](https://www.samba.org/) | SMB/RPC enumeration | Planned / Resource |
| [snmpwalk](https://net-snmp.sourceforge.io/) | SNMP enumeration | Planned / Resource |
| [CeWL](https://github.com/digininja/CeWL) | wordlist generation | Integrated (partial-support) |
| [hashcat](https://github.com/hashcat/hashcat) | hash analysis | Planned / Resource |
| [John the Ripper](https://github.com/openwall/john) | hash analysis | Planned / Resource |

### DNS / API / Proof Ecosystem

| Tool | Role in HunterX | Status |
|---|---|---|
| [dnspython](https://github.com/rthalley/dnspython) | DNS resolution, record enumeration | Integrated (fully-supported) |
| OpenAPI / Swagger parser | OpenAPI analysis, API discovery | Integrated (partial-support) |
| Postman collection parser | API discovery, parameter analysis | Integrated (partial-support) |
| [jwt_tool](https://github.com/ticarpi/jwt_tool) | JWT / authentication analysis | Planned / Resource |
| Proof Replay | proof replay, safe validation | Integrated (fully-supported) |

> **Attribution.** HunterX integrates with and leverages these third-party
> open-source projects. It does not claim ownership of them. Each tool keeps
> its own license and attribution; third-party attribution is preserved in
> [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). Tool names and descriptions are
> used only to document interoperability.

---

## Architecture

The v7 core is a Clean Architecture package under `src/hunterx`:

```
                    HUNTERX v7
                        │
        ┌───────────────┼───────────────┐
        │               │               │
     Missions        Reasoning       Toolchain
        │               │               │
        └───────────────┼───────────────┘
                        │
                  Core Platform
                        │
        ┌───────────────┼───────────────┐
        │               │               │
     Domain       Application     Infrastructure
        │               │               │
        └───────────────┼───────────────┘
                        │
                 Intelligence
                        │
        ┌───────────────┼───────────────┐
        │               │               │
      Evidence       Knowledge       Reporting
```

Package layers:

- `domain` — pure domain layer (entities, ports, services)
- `application` — use-case services
- `infrastructure` — adapters (db, cache, queue, secrets, sandbox)
- `engines` — engine facades (mission, workflow, planner, reasoning,
  correlation, risk, reporting)
- `tools` — tool adapters and the toolchain intelligence layer (SDK,
  intelligence, mastery)
- `agents` — multi-agent platform
- `knowledge`, `reporting`, `config`, `cli`, `api` — delivery layers

See [Architecture](docs/architecture/README.md),
[Foundation](docs/v7-foundation.md) and
[Platform Composition Root](docs/v7-platform-composition-root.md).

## Integrations

- **Security tools** — 92 registered tools across recon, scanning, crawling,
  fuzzing, parameters, validation, secrets, SAST, proxies, exploitation and
  knowledge resources (see the [Tool Ecosystem](#tool-ecosystem) section).
- **AI providers** — LLM-native reasoning through a decoupled AI provider
  layer.
- **CI/CD** — Docker images, SARIF export for GitHub CodeQL, REST API for
  pipeline integration.
- **Persistence** — SQL (SQLite default, PostgreSQL supported) via TIDB with
  Alembic migrations.

---

## Engineering Status

At the v7.0.0 release (2026-08-11):

```text
3,479 tests passed
8 skipped
2 deselected
0 failed
```

The suite spans unit, component, integration, golden, security, acceptance,
performance, engineering, architecture and framework tests, plus the 92-tool
toolchain contract suite. At release, the following quality gates were green:
**pytest, ruff, mypy (eng + shared), bandit (Medium+), vulture, architecture,
docs, compliance, hygiene, dependency and lock-file consistency.**

> **Disclaimer.** These are engineering validation metrics — they document the
> state of the test suite and quality gates at release. They are **not** a
> guarantee of software quality, detection rates, or security assurance.

Local validation commands:

```bash
pytest -m "not tools"        # full default suite
ruff check src eng tests alembic
mypy eng src/hunterx/shared
python -m bandit -r src/hunterx
python -m eng.gates          # all quality gates
```

---

## Target Users

```text
Bug Bounty
→ Turn candidates into reproducible, report-ready findings with minimal PoCs.

Pentesting
→ Orchestrate structured assessments and produce evidence-backed reports.

Red Team
→ Plan missions, orchestrate toolchains, and correlate attack-surface intelligence.

Security Research
→ Investigate unknown and application-specific behavior with hypothesis-driven proof.

Application Security
→ Validate findings with PoC, impact and confidence instead of candidate noise.

DevSecOps / Security Engineering
→ Integrate reproducible results into CI/CD with SARIF and the REST API.
```

---

## Documentation

- [Documentation Hub](docs/documentation.md)
- [Quickstart](docs/quickstart.md)
- [Installation](docs/installation/index.md)
- [Architecture](docs/architecture/README.md)
- [PoC & Validation](docs/poc-validation.md)
- [CLI Reference](docs/cli/index.md)
- [Tool Ecosystem](docs/tool-ecosystem.md)
- [Features](docs/features/index.md)
- [Security](docs/security.md)
- [Responsible Use](docs/responsible-use.md)

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md),
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and the
[Development Bible](docs/bible/README.md). Please report issues via
[GitHub Issues](https://github.com/nullc0d30/HunterX/issues) and ask questions
in [Discussions](https://github.com/nullc0d30/HunterX/discussions).

---

## Responsible Use

HunterX is an authorized cybersecurity testing and research platform. It is
designed to be used **only** against systems you own or are explicitly
authorized to test. You are responsible for:

- Obtaining **appropriate authorization** (written permission) before testing
  any system.
- Complying with all applicable laws, regulations, and terms of service.
- Handling any data discovered during testing responsibly.

The engine never schedules data destruction, persistence, credential dumping,
reverse shells, lateral movement, DoS, mass data extraction or unrestricted
database extraction.

**Disclaimer:** The developer/author (Ahmed Awad / NullC0d3) is not responsible
for misuse, unauthorized access, illegal activity, damage, or any other
unethical use of the software. The software is provided "AS IS" without
warranty of any kind. See [Responsible Use](docs/responsible-use.md).

---

## License

Copyright (c) 2026 Ahmed Awad (AKA NullC0d3). All rights reserved.

Released under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Third-party attribution is in
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

## Author

HunterX is created and maintained by **Ahmed Awad (AKA NullC0d3)** —
Cybersecurity Threat Intelligence Analyst, open-source developer, and security
researcher.

- GitHub: [nullc0d30](https://github.com/nullc0d30)
- Repository: [nullc0d30/HunterX](https://github.com/nullc0d30/HunterX)

## Star / Follow / Contribute

If HunterX helps your authorized security work:

- **Star** the repository — [nullc0d30/HunterX](https://github.com/nullc0d30/HunterX)
- **Try HunterX** — follow the [Quickstart](docs/quickstart.md)
- **Read the documentation** — [Documentation Hub](docs/documentation.md)
- **Contribute** — see [CONTRIBUTING.md](CONTRIBUTING.md)
- **Report issues** — [GitHub Issues](https://github.com/nullc0d30/HunterX/issues)
