<div align="center">

<img src="logo.png" alt="HunterX Official Logo" width="200" height="auto">

# HunterX

**AI-Assisted Vulnerability Discovery, Validation & Proof Engine**

### "Find it. Verify it. Prove it. Report it."

Not just another scanner. HunterX v7 combines reconnaissance, security tooling,
AI-assisted reasoning, vulnerability validation, PoC generation and validation,
evidence collection, correlation, and report generation into one workflow.

An AI-powered offensive security platform for bug bounty researchers,
penetration testers, red teams, security researchers, and security engineers.
It is an authorized cybersecurity testing and research platform.

[![GitHub Release](https://img.shields.io/github/v/release/nullc0d30/HunterX?style=flat-square&logo=github)](https://github.com/nullc0d30/HunterX/releases)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0)
[![Tests](https://img.shields.io/github/actions/workflow/status/nullc0d30/HunterX/test.yml?style=flat-square&label=tests)](https://github.com/nullc0d30/HunterX/actions)
[![Docker](https://img.shields.io/badge/docker-multi--stage-2496ED?style=flat-square&logo=docker)](https://hub.docker.com/r/nullc0d30/hunterx)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat-square)](https://github.com/nullc0d30/HunterX)

**Less noise. More verified findings.**

</div>

> **Responsible use.** HunterX is an authorized cybersecurity testing and
> research platform. You are responsible for obtaining appropriate
> authorization before testing any system. The author is not responsible for
> misuse, unauthorized access, illegal activity, or damage caused by the
> software. See [Responsible Use](#responsible-use) and
> [SECURITY.md](SECURITY.md).

## What is HunterX?

HunterX v7 is an **AI-assisted vulnerability discovery, validation & proof
engine** — an open-source, Clean Architecture Python platform for planning and
running authorized security-assessment missions. It integrates open-source
security tools, normalizes their output into a unified intelligence model,
plans and chains tool executions, and — crucially — **validates hypotheses with
evidence, engineers and replays proofs and PoCs, correlates findings, and
produces professional, report-ready output.**

HunterX does not stop at *"Possible SQL Injection."* It is designed to carry
each candidate through to a **validated finding** that combines:

```
Vulnerability
+ Evidence
+ Reproducibility
+ Impact
+ PoC
===============
Validated Finding
```

## Why HunterX?

Traditional scanners report candidates:

> **Potential SQL Injection** — Confidence: 87%

HunterX targets the full investigation workflow instead:

```
SQL Injection
  ↓ Affected asset
  ↓ Endpoint
  ↓ Parameter
  ↓ Observed behavior
  ↓ Verification
  ↓ Evidence
  ↓ Minimal reproducible PoC
  ↓ PoC validation
  ↓ Impact assessment
  ↓ Report-ready finding
```

Every claim HunterX makes is backed by observations, evidence, validation,
proof, replay records, impact and provenance. A finding is only
`REPORT_READY` when the reportability contract is satisfied.

## From Detection to Proof

A vulnerability detection is **not** a validated finding. HunterX drives each
finding through a lifecycle:

```
DETECTED → SUSPECTED → VALIDATING → VALIDATED → PROVEN → CONFIRMED → REPORT_READY
                                            ↘ FALSE_POSITIVE
                                            ↘ INCONCLUSIVE
```

- `PROVEN` requires a valid, reproducible proof.
- `CONFIRMED` requires the vulnerability-specific proof contract to permit
  confirmation and confidence requirements to be met.
- `REPORT_READY` requires evidence, proof, reproducible PoC, impact,
  confidence, scope, timestamp and provenance.
- A PoC that fails is never automatically a false positive — the engine
  distinguishes `FALSE_POSITIVE` from `INCONCLUSIVE`.

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

HunterX **orchestrates** open-source security tools: it executes them with
structured contracts, parses and normalizes their output into canonical
observations, correlates results, reasons over hypotheses, validates with
evidence, engineers and replays proofs/PoCs, and produces reports. It is
built to work with the ecosystem, not to own every security capability itself.

## v7 Highlights

HunterX v7.0.0 (2026-08-11) is the production-ready v7 release:

- **Composition root** — Clean Architecture `src/hunterx` core (domain,
  application, infrastructure, engines, agents, tools, plugins, knowledge,
  reporting, config, CLI, API) wired through a single platform assembler.
- **Tool integration architecture** — the Tool Integration SDK, tool
  intelligence platform and a 92-tool arsenal manifest with machine-readable
  contracts, structured execution, versioned parsers/normalizers and
  dependency-aware chaining.
- **Autonomous mission orchestration** — create, run, checkpoint, resume and
  finalize full-spectrum security-assessment missions (`hunterx mission`,
  `hunterx hunt`).
- **Adaptive mission planning** — attack-path planning, replanning and
  explainable next-best-action selection.
- **Target intelligence persistence (TIDB)** — SQL storage with Alembic
  migrations, events, audit and versioning; structured target intelligence
  (assets, targets, observations, findings, evidence, history, relationships).
- **Cloud & SaaS intelligence** — evidence-backed cloud/SaaS attack-surface
  intelligence across providers (AWS, Azure, GCP, OCI, Cloudflare,
  DigitalOcean, Akamai, Fastly, Vercel, Netlify, Heroku, Render, Fly.io,
  Supabase, Firebase, Kubernetes, Docker).
- **Topology & events** — network/cloud topology relationships and a typed
  event bus with observability.
- **Knowledge & correlation** — knowledge graph relationships, cross-tool
  correlation and evidence chains.
- **PoC / evidence architecture** — the Vulnerability Proof & PoC Validation
  Engine: proof contracts, minimal safe proofs, replay, reproducibility,
  impact and evidence-driven confidence.
- **Professional reporting** — findings, evidence bundles, remediation plans
  and multi-format exports (Markdown, HTML, JSON, SARIF, PDF, package).
- **Security hardening** — scope and authorization guards, sandboxing,
  evidence-gated confidence, secret masking, hardened XML parsing.
- **Installation system** — idempotent `install.sh` v7 installer, Docker
  multi-stage image, PyPI packaging.
- **CI/CD** — lint, type, test, security, supply-chain, packaging and release
  pipelines.
- **Documentation** — comprehensive v7 docs and product site.
- **Production readiness** — final hardening, release-tree and architecture
  certification.

Engineering validation at release: **3479 tests passed, 8 skipped,
2 deselected, 0 failed** (ruff, mypy, bandit, vulture, docs and package gates
green). This is an engineering validation metric, not a quality guarantee.

## Security Coverage

HunterX supports vulnerability discovery, validation and proof across a broad
set of classes, including (as supported by its proof-contract registry):

SQL injection · NoSQL injection · XSS · SSRF · Path traversal / LFI · RCE /
command injection indicators · IDOR / BOLA · SSTI · XXE · authentication and
authorization issues · API/GraphQL issues · open redirect · CORS · sensitive
information exposure · security misconfiguration · known vulnerable components ·
dependency vulnerabilities · cloud exposure · novel / unknown behavior
(`UNKNOWN_BEHAVIOR`).

The engine is **not a weaponization engine**: it demonstrates vulnerabilities
with minimum necessary interaction and impact. Data destruction, persistence,
credential dumping, reverse shells, lateral movement, DoS, mass data extraction
and unrestricted database extraction are never scheduled.

## Tool Ecosystem

HunterX is **built to work with the security-tooling ecosystem**. It integrates
with, executes, parses, normalizes and correlates output from the tools below
where the actual v7 implementation supports them. Integration status per tool
is tracked in the [toolchain manifest](capabilities/full-toolchain-intelligence.json)
and on the [Tool Ecosystem](docs/tool-ecosystem.md) page. Status labels:

- **Integrated (fully-supported)** — structured execution, parser and
  normalizer.
- **Integrated (partial-support)** — parser/normalizer or adapter with
  documented limitations.
- **Planned / Resource** — registered as a knowledge resource or known tool;
  not claimed as direct execution.

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
| [SearchSploit](https://gitlab.com/exploit-database/exploitdb) | exploit research | Integrated (fully-supported) |
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

> **Attribution.** HunterX integrates with and leverages these third-party
> open-source projects. It does not claim ownership of them. Each tool keeps
> its own license and attribution; third-party attribution is preserved in
> [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). Tool names and descriptions are
> used only to document interoperability.

## PoC & Proof Engine

HunterX treats **proof as part of vulnerability validation**. The proof engine
transforms a validated hypothesis into a report-ready finding:

```
HYPOTHESIS → PROOF CONTRACT → REQUIRED EVIDENCE → MINIMAL PROOF STRATEGY →
PROOF CONSTRUCTION → SAFETY VALIDATION → SCOPE VALIDATION → EXECUTION →
REPLAY → EVIDENCE EVALUATION → IMPACT → CONFIDENCE → VALIDATED FINDING →
REPRODUCTION PACKAGE → REPORT
```

- **Proof contracts** define, per vulnerability class, preconditions, allowed
  and forbidden actions, required evidence, expected behavior, replay and
  impact requirements. Classes include SQL/NoSQL injection, XSS, SSRF, path
  traversal/LFI, IDOR, authentication, authorization, SSTI, XXE, command
  injection indicators, cloud exposure and `UNKNOWN_BEHAVIOR` (novel).
- **Minimal, safe proofs** — PoCs are structured artifacts (request templates,
  differential tests, configuration snapshots), never arbitrary executable
  scripts. `GENERATED` ≠ `VALIDATED`; `EXECUTED` ≠ `VALIDATED`.
- **Replay & reproducibility** — proofs are replayed deterministically;
  `REPRODUCIBLE` requires repeated successful replays, never a single run.
- **Evidence-driven impact and confidence** — impact is classified strictly
  from captured evidence; confidence is a versioned, weighted policy over
  named factors — never a universal percentage.
- **Novel behavior** — unknown behaviors follow a hypothesis-driven loop:
  `Unknown Behavior → Hypothesis → Experiment → Unexpected Result → New
  Hypothesis → Minimal Proof → Validated Finding`. HunterX supports
  hypothesis-driven discovery and investigation of unknown or
  application-specific behaviors; it does not claim guaranteed autonomous
  discovery of zero-days.
- **RCE, responsibly** — where applicable, proof emphasizes minimal-impact
  demonstration, evidence of execution, and reproducibility — not destructive
  commands.

## Target Intelligence

HunterX maintains **structured target intelligence** rather than treating every
scan as an isolated command. v7 persists and correlates:

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

## Cloud & SaaS Intelligence

HunterX v7 includes evidence-backed **Cloud & SaaS Attack-Surface Intelligence**.
Where supported, provider coverage includes **AWS, Azure, GCP, OCI, Cloudflare,
DigitalOcean, Akamai, Fastly, Vercel, Netlify, Heroku, Render, Fly.io,
Supabase, Firebase, Kubernetes and Docker**.

It provides provider detection, cloud resource intelligence, exposure
classification, environment classification, topology, account/region/resource
relationships, SaaS detection, cloud evidence and correlation — built from
passive, static evidence (DNS, TLS, HTTP headers, HTML/JS, OpenAPI,
documentation) for authorized targets. It never authenticates to cloud
accounts, never accesses cloud resources and never retrieves secrets.

## Knowledge Graph & Correlation

HunterX correlates results across tools and missions into a knowledge graph of
entities and relationships (targets, assets, observations, findings, evidence,
proofs, attack paths). This enables cross-scan correlation, attack-path
analysis and context-aware reasoning.

## Reporting

The workflow does not end at detection. HunterX turns validated findings into
structured, professional reports with verified export formats:

- **JSON** — machine-parsable
- **Markdown** — human-readable
- **HTML** — visual dashboard
- **SARIF 2.1** — VS Code / GitHub CodeQL integration
- **PDF** — document export
- **package** — evidence bundles (ZIP)

Reports include finding, asset, endpoint, parameter, evidence, verification,
PoC, reproduction, impact, confidence, relationships, risk/context, and
remediation/recommendations where supported. Every statement traces to
observation, evidence, validation, proof, impact, tool result, target
intelligence or explicit analyst reasoning.

## Usage

HunterX v7 organizes work as **missions**. Start with an authorized target:

```bash
# Plan and start a full-spectrum hunt mission
hunterx hunt full_security_assessment https://example.com

# Track it
hunterx hunt status <mission_id>
hunterx hunt surface <mission_id>

# Inspect the toolchain
hunterx tools list
hunterx tools capabilities
hunterx tools health

# Findings and reports
hunterx finding list <mission_id>
hunterx report generate <finding_id>
hunterx report export <report_id> markdown
```

Missions persist to the configured database (SQLite by default), so
`hunterx mission create <objective> <target>` followed by
`hunterx mission start <mission_id>` works across CLI invocations.

## Example Workflow

```bash
# Plan and start a full-spectrum hunt mission against an authorized target
hunterx hunt full_security_assessment https://example.com

# Track mission state and surface
hunterx hunt status <mission_id>
hunterx hunt surface <mission_id>

# Inspect the integrated toolchain
hunterx tools list
hunterx tools capabilities
hunterx tools health

# Work with findings, proofs and reports
hunterx finding list <mission_id>
hunterx finding poc <finding_id>       # PoC engineering
hunterx finding proof <finding_id>     # proof state
hunterx finding replay <finding_id>    # proof replay
hunterx report generate <finding_id>
hunterx report export <report_id> sarif
```

## Installation

Requirements: **Python 3.11+** on Linux, macOS or Windows.

```bash
# Installer script (Linux/macOS)
curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash

# Or from source
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
python -m pip install -e ".[api,db,dev]"
```

> **Name note.** The GitHub repository
> [nullc0d30/HunterX](https://github.com/nullc0d30/HunterX) is the canonical
> home of HunterX, created and maintained by Ahmed Awad (AKA NullC0d3). A
> different, unrelated Python project also uses the name `hunterx` on PyPI.
> Always install HunterX from this repository (or `install.sh`) to get the
> correct, current project.

Verify:

```bash
hunterx version     # HunterX v7.0.0
hunterx help        # command list
hunterx platform    # platform composition
hunterx config      # resolved configuration
```

See [docs/installation](docs/installation/index.md) for details, including
database initialization (`alembic upgrade head`) and Docker.

## CLI

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

See [docs/cli](docs/cli/index.md) for the full reference.

## REST API

The v7 REST API is a FastAPI application (`hunterx.api.app:create_app`).
Install from source with the `api` extra and run:

```bash
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
python -m pip install -e ".[api]"
uvicorn hunterx.api.app:create_app --host 127.0.0.1 --port 8080
```

API-key authentication is opt-in (admin/read-only roles). See
[docs](docs/documentation.md).

## Docker

```bash
docker build -t nullc0d30/hunterx:7.0.0 .
docker compose up -d hunterx-api
```

The container runs as a non-root user. See
[docs/v7-release-guide.md](docs/v7-release-guide.md).

## Architecture

The v7 core is a Clean Architecture package under `src/hunterx`:

- `domain` — pure domain layer (entities, ports, services)
- `application` — use-case services
- `infrastructure` — adapters (db, cache, queue, secrets, sandbox)
- `engines` — engine facades (mission, workflow, planner, reasoning,
  correlation, risk, reporting)
- `tools` — tool adapters and the toolchain intelligence layer (SDK,
  intelligence, mastery)
- `agents` — multi-agent platform
- `knowledge`, `reporting`, `config`, `cli`, `api` — delivery layers

See [docs/architecture](docs/architecture/README.md),
[docs/v7-foundation.md](docs/v7-foundation.md) and
[docs/v7-platform-composition-root.md](docs/v7-platform-composition-root.md).

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

## Testing & Quality

```bash
pytest -m "not tools"        # full default suite
ruff check src eng tests alembic
mypy eng src/hunterx/shared
python -m bandit -r src/hunterx
python -m eng.gates          # all quality gates
```

## Target Users

- **Bug bounty hunters** — evidence-backed findings, minimal reproducible PoCs,
  report-ready packages.
- **Penetration testers** — structured missions, professional reports,
  remediation and retest planning.
- **Red teams** — mission orchestration, attack-path planning, cloud/SaaS
  intelligence, knowledge-graph correlation.
- **Security researchers** — hypothesis-driven investigation of unknown and
  application-specific behaviors.
- **Application security engineers** — validated findings with PoC, impact and
  confidence instead of candidate noise.
- **DevSecOps / security engineering teams** — CI/CD integration, SARIF,
  REST API, reproducible results.

## Documentation

- [Documentation Hub](docs/documentation.md)
- [Installation](docs/installation/index.md)
- [CLI Reference](docs/cli/index.md)
- [Quickstart](docs/quickstart.md)
- [Tool Ecosystem](docs/tool-ecosystem.md)
- [PoC & Validation](docs/poc-validation.md)
- [Features](docs/features/index.md)
- [Security](docs/security.md)
- [Responsible Use](docs/responsible-use.md)

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md),
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and the
[Development Bible](docs/bible/README.md). Please report issues via
[GitHub Issues](https://github.com/nullc0d30/HunterX/issues) and ask questions
in [Discussions](https://github.com/nullc0d30/HunterX/discussions).

## Responsible Use

HunterX is an authorized cybersecurity testing and research platform. It is
designed to be used **only** against systems you own or are explicitly
authorized to test. You are responsible for:

- Obtaining **appropriate authorization** (written permission) before testing
  any system.
- Complying with all applicable laws, regulations, and terms of service.
- Handling any data discovered during testing responsibly.

**Disclaimer:** The developer/author (Ahmed Awad / NullC0d3) is not responsible
for misuse, unauthorized access, illegal activity, damage, or any other
unethical use of the software. The software is provided "AS IS" without
warranty of any kind. See [docs/responsible-use.md](docs/responsible-use.md).

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
