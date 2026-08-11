---
layout: default
title: Tool Mastery — Universal Security Arsenal — HunterX
permalink: /v7-tool-mastery/
---

# Tool Mastery — Universal Security Arsenal

Sprint 025 turns HunterX from "an orchestrator that can execute security tools"
into **a professional security operator that understands and correctly uses
every integrated tool**. The mastery layer composes the Tool Intelligence
Platform (TIP) with:

- a **universal security arsenal** — machine-readable tool profiles,
- a **relationship graph** — how tools chain, validate and replace each other,
- **data-driven playbooks** — objective + capability playbooks, never raw commands,
- **mission-aware selection** — explainable, safety-ceilinged tool choice,
- **target-specific history** — what ran, what was learned, what remains unknown,
- **coverage analysis** — what is fully supported vs. knowledge-only,
- **dataset provenance** — versioned, licensed, rollback-capable datasets,
- **version awareness** — installed version vs. declared constraints,
- **parser regression & result replay** — replay raw output without re-running tools.

## Facade

```python
from hunterx.tools.mastery.api import ToolMasteryAPI

mastery = ToolMasteryAPI()          # seeds the full Sprint 025 arsenal
mastery.get_profile("nuclei")       # -> ToolMasterProfile
mastery.select_best("xss-validation", mission_type="bug-bounty")
mastery.coverage()                  # -> ToolCoverageReport
mastery.arsenal().export("capabilities/universal-security-arsenal.json")
```

When wired through the platform, the facade is available as
`platform.mastery` and resolvable from the container as
`ToolMasteryAPI` / `ToolMasteryPort`:

```python
from hunterx.domain.ports.tool_mastery import ToolMasteryPort
platform = build_platform()
platform.resolve(ToolMasteryPort).select("sqli-validation")
```

## Canonical data

The Sprint 025 arsenal is declared as compact `ToolSpec` records grouped by
domain (see `src/hunterx/tools/mastery/`):

| Module | Tools |
|---|---|
| `arsenal_recon.py` | subfinder, amass, assetfinder, findomain, bbot, dnsx, naabu, nmap, masscan, ... |
| `arsenal_web.py` | httpx, katana, ffuf, feroxbuster, arjun, kiterunner, graphqlmap, jsluice, ... |
| `arsenal_analysis.py` | nuclei, dalfox, sqlmap, commix, sstimap, interactsh, gitleaks, semgrep, zap, ... |
| `arsenal_enterprise.py` | netexec, impacket, enum4linux-ng, snmpwalk, prowler, trivy, syft, osv-scanner, ... |
| `arsenal_exploit.py` | metasploit, searchsploit, exploitdb, cewl, hashcat, john |

Each `ToolSpec` expands into a full `ToolMasterProfile` (identity + knowledge +
support classification + evidence/proof semantics + chaining + safety). The
single machine-readable view is the **universal security arsenal manifest** at
`capabilities/universal-security-arsenal.json`.

Playbooks, relationships and datasets are declared in:

- `playbook_data.py` — 17 canonical playbooks (`web-initial-recon`, `api-discovery`,
  `subdomain-enumeration`, `network-recon`, `web-content-discovery`,
  `javascript-analysis`, `secret-discovery`, `vulnerability-triage`,
  `xss-validation`, `sqli-validation`, `ssrf-validation`, `ssti-validation`,
  `xxe-validation`, `graphql-assessment`, `cloud-assessment`,
  `container-assessment`, `active-directory-assessment`).
- `relationship_data.py` — 68 edges (enables / follows / validates / replaces / ...).
- `dataset_data.py` — 13 datasets (SecLists, FuzzDB, PayloadsAllTheThings,
  Nuclei templates, Semgrep rules, Gitleaks rules, Trivy/Grype/OSV DBs,
  ExploitDB, CeWL wordlists, Interactsh patterns).

## Principles

- **Tool output is never truth.** A clean scan is never automatically
  `NOT_VULNERABLE`; a template match is a *candidate* until validated.
- **Playbooks declare objectives and capabilities**, never unrestricted attack
  commands. Concrete tool choice is delegated to the mission-aware selector.
- **Selection is explainable and safety-ceilinged.** A tool above the mission
  authorization ceiling is never selected.
- **Full support is earned.** A tool is `FULLY_SUPPORTED` only when execution,
  parsing, normalization, capability knowledge, evidence mapping, error
  handling, version handling, scope, safety and tests are all implemented.
- **Datasets are knowledge, not executable truth**, and every update is
  versioned, validated, auditable and rollback-capable.

## Regeneration

The manifest is regenerated from source data by running:

```sh
python -m pytest -q tests/engineering/test_regenerate_arsenal.py
```
