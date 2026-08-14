---
layout: default
title: CLI Reference — HunterX v7
keywords: HunterX CLI, Command Line Interface, hunterx commands
description: >-
  Reference for the HunterX v7 command-line interface: missions, hunts,
  findings, reports, targets, campaigns and the toolchain.
---

# CLI Reference

HunterX v7 ships a single `hunterx` command (plus the `hunterx-arch` architecture
linter for developers). Commands are grouped by capability.

## Global commands

| Command | Description |
|---|---|
| `hunterx version` | Show the platform version |
| `hunterx help` | Show all commands |
| `hunterx config` | Show the resolved configuration (JSON) |
| `hunterx platform` | Show platform composition status |

## Missions (autonomous orchestration)

| Command | Description |
|---|---|
| `hunterx mission create [objective] [target]` | Create an autonomous mission |
| `hunterx mission start <mission_id>` | Start a mission run |
| `hunterx mission status <mission_id>` | Show mission status |
| `hunterx mission pause / resume / cancel / finalize` | Mission lifecycle |
| `hunterx mission timeline / decisions / hypotheses / findings` | Mission data |
| `hunterx mission attack-paths / coverage / tools` | Mission intelligence |

## Hunts (full-spectrum)

| Command | Description |
|---|---|
| `hunterx hunt [objective] [target]` | Create and start a hunt mission |
| `hunterx hunt status / surface / coverage` | Mission overview |
| `hunterx hunt findings / evidence / proofs` | Results |
| `hunterx hunt paths / timeline` | Attack paths and history |

## Adaptive mission planning

| Command | Description |
|---|---|
| `hunterx mission plan [objective] [target]` | Create an adaptive mission |
| `hunterx mission replan / pause / resume` | Adaptive lifecycle |
| `hunterx mission paths / explain` | Attack paths and next action |

## Findings (evidence-driven)

| Command | Description |
|---|---|
| `hunterx finding create / list / show` | Finding lifecycle |
| `hunterx finding evidence / validate` | Evidence assessment |
| `hunterx finding poc / proof / replay` | PoC engineering |
| `hunterx finding explain / report-ready` | Confidence and readiness |

## Reports (professional)

| Command | Description |
|---|---|
| `hunterx report list / show / preview / validate` | Report lifecycle |
| `hunterx report generate / export` | Generate and export (markdown/html/json/sarif/pdf/package) |
| `hunterx report evidence / timeline / remediation / retest` | Report data |
| `hunterx report sarif` | SARIF export |

## Targets & campaigns

| Command | Description |
|---|---|
| `hunterx target memory / snapshot / diff` | Target intelligence |
| `hunterx target changes / history / coverage / gaps / risk / revalidate` | Target memory |
| `hunterx campaign list / show / intelligence` | Campaign intelligence |

## Toolchain

| Command | Description |
|---|---|
| `hunterx tools list / show / contract / contracts` | Tool knowledge |
| `hunterx tools capabilities / health / versions` | Capability catalog |
| `hunterx tools execute <tool_id> <target> [--parameters JSON]` | Structured execution |
| `hunterx tools inspect-result / parse / normalize` | Output processing |
| `hunterx tools chain / chain-execute / recommend` | Chaining |

## Tool readiness & provisioning

| Command | Description |
|---|---|
| `hunterx install [--profile <name>]` | Establish the base HunterX environment (detect + verify tools) |
| `hunterx tools check [--json]` | Show per-tool readiness and capability coverage |
| `hunterx tools install [--profile <name>] [tool_id ...]` | Provision missing tools via trusted static methods |
| `hunterx tools audit [--json]` | Show tool integration maturity (knowledge + runtime) |

Install profiles: `minimal`, `recon`, `web`, `network`, `vulnerability`, `full`.

## Examples

```bash
hunterx version
hunterx platform
hunterx install
hunterx tools check
hunterx tools install --profile full
hunterx tools list
hunterx hunt full_security_assessment https://example.com
hunterx finding list <mission_id>
hunterx report generate <finding_id>
```

## See also

- [Quickstart]({{ '/quickstart/' | relative_url }}) — run a first mission
- [Configuration]({{ '/configuration/' | relative_url }}) — environment overrides
- [Architecture]({{ '/architecture/' | relative_url }}) — platform internals
