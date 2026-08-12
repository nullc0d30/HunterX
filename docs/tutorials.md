---
layout: default
title: Tutorials — HunterX v7
keywords: HunterX tutorial, HunterX guide, security testing tutorial, vulnerability validation tutorial, PoC tutorial, HunterX how-to
description: >-
  Tutorials and step-by-step guides for HunterX v7: installation, first
  missions, findings and reports, PoC engineering and security-assessment
  workflows.
---

# Tutorials

Step-by-step guides for getting real work done with HunterX v7. All examples
assume you have authorization to test the targets you use.

## Getting started

1. **Install HunterX** — [Installation]({{ '/installation/' | relative_url }}) covers the installer,
   source installs, plus Docker.
2. **Run your first mission** — [Quickstart]({{ '/quickstart/' | relative_url }}) walks through a
   full-spectrum hunt mission against an authorized target.
3. **Explore the CLI** — [CLI Reference]({{ '/cli/' | relative_url }}) documents every `hunterx`
   command group (missions, hunts, findings, reports, targets, toolchain).

## Core workflows

- **Findings, proofs and reports** — use `hunterx finding list`,
  `hunterx finding poc/proof/replay`, `hunterx report generate` and
  `hunterx report export` to move from discovery to report-ready findings.
  See [PoC & Validation]({{ '/poc-validation/' | relative_url }}).
- **Toolchain intelligence** — `hunterx tools list`, `hunterx tools
  capabilities`, `hunterx tools health`, `hunterx tools execute` and
  `hunterx tools chain` for structured tool orchestration. See
  [Tool Ecosystem]({{ '/tool-ecosystem/' | relative_url }}).
- **Target memory** — `hunterx target memory/snapshot/diff/changes/history`
  for target intelligence and change detection. See
  [Target Memory & Campaign Intelligence]({{ '/v7-target-memory-and-campaign-intelligence/' | relative_url }}).

## Workflows by role

- [Bug bounty workflow]({{ '/bug-bounty/' | relative_url }}) — from recon to reportable finding.
- [Red team mission]({{ '/red-team/' | relative_url }}) — mission orchestration and attack paths.
- [CI/CD security scanning]({{ '/ci-cd-security-scanning/' | relative_url }}) — pipeline integration
  with Docker, REST API and SARIF.

## Blog tutorials

The [HunterX blog]({{ '/blog/' | relative_url }}) publishes practical technical articles, including
bug-bounty workflows, Docker production guides and reasoning-pipeline
deep dives.

## Related

- [Documentation Hub]({{ '/documentation/' | relative_url }})
- [FAQ]({{ '/faq/' | relative_url }})
- [Glossary]({{ '/glossary/' | relative_url }})
- [Responsible Use]({{ '/responsible-use/' | relative_url }})
