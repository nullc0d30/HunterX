<div align="center">

<img src="https://raw.githubusercontent.com/nullc0d30/HunterX/main/docs/assets/images/logof.png" alt="HunterX official logo" width="220" height="auto">

# HunterX

## AI-Directed Autonomous Security Assessment Engine

### Observe. Reason. Test. Validate. Prove. Report.

HunterX is an **AI-directed autonomous security assessment engine** for planning and executing authorized security-assessment missions. It combines **reconnaissance**, **tool orchestration**, **AI-directed strategic decision-making**, **active security testing**, **validation**, **proof**, **evidence**, **replay**, **correlation**, **impact assessment**, and **professional reporting** into a single autonomous workflow.

[![GitHub Release](https://img.shields.io/github/v/release/nullc0d30/HunterX?style=flat-square&logo=github)](https://github.com/nullc0d30/HunterX/releases)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square)](https://www.apache.org/licenses/LICENSE-2.0)
[![Tests](https://img.shields.io/github/actions/workflow/status/nullc0d30/HunterX/test.yml?style=flat-square&label=tests)](https://github.com/nullc0d30/HunterX/actions)
[![Docker](https://img.shields.io/badge/docker-multi--stage-2496ED?style=flat-square&logo=docker)](https://hub.docker.com/r/nullc0d30/hunterx)
[![PyPI](https://img.shields.io/pypi/v/hunterxsec?style=flat-square&logo=pypi&label=pypi)](https://pypi.org/project/hunterxsec/)
[![OWASP Community](https://img.shields.io/badge/OWASP%20Community-listed-green?style=flat-square&logo=owasp)](https://owasp.org/www-community/Vulnerability_Scanning_Tools)
[![Awesome](https://img.shields.io/badge/Awesome-listed-informational?style=flat-square&logo=awesome-lists)](https://awesome.re/)
[![Awesome Red Teaming](https://img.shields.io/badge/Awesome%20Red%20Teaming-listed-informational?style=flat-square&logo=awesome-lists)](https://github.com/0xMrNiko/Awesome-Red-Teaming)
[![Awesome AI in Cybersecurity](https://img.shields.io/badge/Awesome%20AI%20in%20Cybersecurity-listed-informational?style=flat-square&logo=awesome-lists)](https://github.com/ElNiak/awesome-ai-cybersecurity)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat-square)](https://github.com/nullc0d30/HunterX)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/nullc0d30?style=flat-square&logo=github)](https://github.com/sponsors/nullc0d30)

**Autonomous security assessment. Verified evidence. Report-ready findings.**

</div>

---

## What HunterX Is

HunterX is an **AI-directed autonomous security assessment engine**. It is not a scanner. It does not stop at detection.

HunterX directs the complete security assessment lifecycle: it **discovers**, **reasons**, **selects the next security question**, **executes the appropriate capability**, **observes the result**, **validates the evidence**, **proves the finding**, **reassesses**, and **continues** until genuine exhaustion. It is an autonomous security assessment engine that orchestrates the entire workflow—reconnaissance, active security testing, validation, proof, evidence, replay, correlation, and reporting—under AI direction.

HunterX provides the execution engine, tool orchestration, policy enforcement, scope enforcement, security-test state management, evidence management, validation, proof generation, replay, correlation, reporting, and resource controls. The AI Hunt Director is the strategic decision-maker.

---

## Why HunterX Is Different

| Traditional Scanner | HunterX |
|---|---|
| Stops at "possible vulnerability" | Carries candidate through validation, proof, and replay |
| Fixed tool sequence | AI-directed adaptive test selection |
| No validation | Active testing → validation → proof → replay |
| No proof | Proof contracts, minimal safe PoCs, deterministic replay |
| No replay | Deterministic replay with verdict |
| No correlation | Cross-tool evidence chains, attack paths, knowledge graph |
| No strategic direction | AI Hunt Director selects next security question |

**AI-directed adaptive testing** — The AI Hunt Director receives the complete mission state and available tool capabilities, then decides the next security question and capability to execute.

**Multi-tool orchestration** — 92+ external security tools orchestrated through capability contracts, not hardcoded pipelines.

**Active security testing** — Not just discovery. SQL injection, SSRF, IDOR, XSS, path traversal, command injection, SSTI, XXE, authentication, authorization, API, GraphQL, JWT, cloud misconfiguration, business logic, client-side, and more—all actively tested.

**Validation → Proof → Replay** — Every finding passes through validation, proof contracts, minimal safe PoC generation, deterministic replay with verdict, and reproducibility requirements.

**Evidence & Replay** — Every finding is backed by evidence chains, proof artifacts, and deterministic replay records with verdict.

**Correlation & Reporting** — Cross-tool evidence chains, attack paths, knowledge graph, and professional multi-format reports (Markdown, HTML, JSON, SARIF 2.1, PDF, evidence packages).

---

## How It Works

```
TARGET
  ↓
AI HUNT DIRECTOR
  ↓
SECURITY TEST SELECTION
  ↓
CAPABILITY / TOOL EXECUTION
  ↓
OBSERVE
  ↓
VALIDATE / PROVE
  ↓
REASSESS
  ↓
NEXT TEST
  ↓
GENUINE EXHAUSTION
```

The **AI Hunt Director** is the strategic decision-maker. It receives the complete mission state—target, scope, authorization, current phase, discovered technologies, services, endpoints, parameters, observations, negative evidence, hypotheses, findings, evidence, proofs, attack paths, previous actions, available tools with capability schemas, resource budget, and Security Test Matrix—and decides the next security question, the capability to execute, and the arguments.

HunterX provides the execution engine, tool orchestration, policy enforcement, scope enforcement, security-test state, evidence management, validation, proof generation, replay, correlation, reporting, and resource controls. The AI directs; HunterX executes and enforces.

---

## What Full Security Assessment Means

`full_security_assessment` is **not**:
- Reconnaissance only
- Endpoint enumeration only  
- Hypothesis generation only
- A fixed tool sequence

`full_security_assessment` **means**:

1. **Discover** — Assets, services, technologies, endpoints, parameters, API schemas, JavaScript, authentication mechanisms
2. **Assess** — Map attack surface, fingerprint technologies, enumerate parameters, map APIs
3. **Actively Test** — SQL/NoSQL injection, SSRF, IDOR/BOLA, XSS, path traversal/LFI, command injection, SSTI, XXE, authentication, session, authorization, API/GraphQL, business logic, client-side, JWT/token, cloud misconfiguration, sensitive data exposure, information disclosure, open redirect, CORS, CSRF, HTTP methods, rate limiting, input validation
4. **Validate** — Differential probes, evidence evaluation, negative evidence, hypothesis state transitions
4. **Prove** — Proof contracts, minimal safe PoCs, safety/scope validation, deterministic execution
5. **Replay** — Deterministic replay with verdict (SUCCESS/FAILED/INCONCLUSIVE/BLOCKED), reproducibility requirements
6. **Correlate** — Cross-tool evidence chains, attack paths, knowledge graph, impact assessment
7. **Reassess** — AI reassesses after every result; new evidence changes the next decision
8. **Report** — Multi-format professional reports with evidence traceability

Security-testing domains are evaluated based on applicability. The Security Test Matrix tracks each domain: `NOT_ASSESSED` → `IN_PROGRESS` → `TESTED_NEGATIVE` / `TESTED_POSITIVE_VALIDATED` / `NOT_APPLICABLE_WITH_EVIDENCE` / `BLOCKED_WITH_REASON`. The mission completes only when all applicable domains reach terminal states.

---

## AI Providers (Summary)

HunterX supports cloud and local AI providers. Provider and model are selected independently.

**Cloud:** OpenRouter, OpenAI, Anthropic, DeepSeek, Google Gemini, xAI/Grok, Requesty (OpenAI-compatible)

**Local:** LM Studio (`lmstudio`), Ollama (`ollama`), generic OpenAI-compatible endpoints

**Minimal configuration:**
```env
HUNTERX_AI_PROVIDER=openrouter
HUNTERX_AI_MODEL=deepseek/deepseek-chat
HUNTERX_AI_OPENROUTER_KEY=sk-or-...
```

Local (Ollama):
```env
HUNTERX_AI_PROVIDER=ollama
HUNTERX_AI_MODEL=qwen2.5:3b-instruct
HUNTERX_AI_BASE_URL=http://127.0.0.1:11434/v1
```

**Guided configuration:** `hunterx ai configure` — interactive provider/model/key setup with validation.

Full reference: [docs/configuration/ai.md](docs/configuration/ai.md) | [GitHub Pages](https://nullc0d30.github.io/HunterX/configuration/ai/)

---

## Quick Start

```bash
# 1. INSTALL
pip install hunterxsec
# or: curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash

# 2. TOOLS READY
hunterx install                          # base environment + detect/verify tools
hunterx tools check                      # readiness + capability coverage

# 3. AI CHECK (optional)
hunterx ai check                         # verify provider connectivity + model

# 4. HUNT - AI-directed autonomous assessment
hunterx hunt full_security_assessment https://example.com

# Deterministic mode (explicit, no AI)
hunterx hunt --deterministic full_security_assessment https://example.com

# 4. INSPECT
hunterx hunt status <mission_id>
hunterx hunt surface <mission_id>

# 5. VALIDATE
hunterx finding list <mission_id>
hunterx finding poc <finding_id>
hunterx finding proof <finding_id>
hunterx finding replay <finding_id>

# 6. REPORT
hunterx report generate <finding_id>
hunterx report export <report_id> markdown
```

**Note:** `hunterx hunt --deterministic` is an **explicit** deterministic mode. It is **not equivalent** to AI-directed autonomous mode. It bypasses the AI Hunt Director entirely. For `full_security_assessment`, if AI is required by the autonomous mode and unavailable, HunterX clearly instructs the user how to configure it rather than silently pretending deterministic execution is equivalent.

---

## Security Model

- **Scope enforcement** — Every target validated against authorized scope before execution; third-party domains never become targets
- **Authorization** — Explicit authorization context required; scope never expands implicitly
- **Policy gate** — Every AI decision validated against scope, authorization, budget, tool availability, and safety before execution
- **Safe proof** — Minimal-impact PoCs, bounded inputs, forbidden markers refused, secrets redacted, immutable lineage
- **No destructive weaponization** — No data destruction, persistence, credential dumping, reverse shells, lateral movement, DoS, mass extraction
- **Evidence-backed findings** — Every finding traces to observation, evidence, validation, proof, replay, impact, tool result, or explicit analyst reasoning

---

## Findings and Proof

```
DETECTION
  ↓
HYPOTHESIS
  ↓
ACTIVE TEST
  ↓
EVIDENCE
  ↓
VALIDATION
  ↓
PROOF CONTRACT
  ↓
MINIMAL SAFE PROOF
  ↓
DETERMINISTIC REPLAY (SUCCESS/FAILED/INCONCLUSIVE/BLOCKED)
  ↓
REPRODUCIBILITY (repeated successful replays)
  ↓
REPORT-READY FINDING
```

Every finding passes through validation, proof contract, minimal safe proof generation, deterministic replay with verdict, and reproducibility requirements before reaching `REPORT_READY`.

---

## Tool Ecosystem

HunterX orchestrates 92+ external security tools through capability contracts: nmap, subfinder, nuclei, ffuf, arjun, sqlmap, dalfox, xssstrike, ghau, commix, tplmap, xxeinjector, interactsh, katana, gospider, hakrawler, gau, waybackurls, ffuf, feroxbuster, dirsearch, arjun, paramspider, kiterunner, whatweb, httpx, dnsx, massdns, shuffledns, masscan, naabu, rustscan, nmap, osv-scanner, trivy, prowler, scoutsuite, and more.

Tools are discovered, verified, and provisioned **before** a mission runs. `hunterx tools check` shows per-tool status and per-capability coverage.

Full reference: [docs/tool-ecosystem.md](docs/tool-ecosystem.md) | [Tool Readiness](docs/tool-readiness.md)

---

## Reporting

Professional multi-format reports with evidence traceability:

| Format | Purpose |
|---|---|
| Markdown | Human-readable |
| HTML | Visual dashboard |
| JSON | Machine-parsable |
| SARIF 2.1 | VS Code / GitHub CodeQL integration |
| PDF | Document export |
| Evidence Package (ZIP) | Bundled evidence |

Every statement traces to observation, evidence, validation, proof, replay, impact, tool result, target intelligence, or explicit analyst reasoning.

---

## Documentation

| Topic | Link |
|---|---|
| **Installation** | [docs/installation/index.md](docs/installation/index.md) |
| **AI Configuration** | [docs/configuration/ai.md](docs/configuration/ai.md) |
| **CLI Reference** | [docs/cli/index.md](docs/cli/index.md) |
| **Tool Ecosystem** | [docs/tool-ecosystem.md](docs/tool-ecosystem.md) |
| **Tool Readiness** | [docs/tool-readiness.md](docs/tool-readiness.md) |
| **Proof / Validation** | [docs/poc-validation.md](docs/poc-validation.md) |
| **Responsible Use** | [docs/responsible-use.md](docs/responsible-use.md) |
| **Security** | [SECURITY.md](SECURITY.md) |
| **Release Notes** | [CHANGELOG.md](CHANGELOG.md) |

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. All PRs must pass tests and linting.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

## Responsible Use

HunterX is an authorized cybersecurity testing and research platform. You are responsible for obtaining appropriate authorization before testing any system. The author is not responsible for misuse, unauthorized access, illegal activity, or damage caused by the software. See [Responsible Use](docs/responsible-use.md) and [SECURITY.md](SECURITY.md).