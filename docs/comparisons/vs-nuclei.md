---
layout: default
title: HunterX vs Nuclei — Comparison
keywords: HunterX vs Nuclei, Nuclei comparison, template based vulnerability scanner, Nuclei integration
description: >-
  HunterX vs Nuclei: how the AI-assisted vulnerability discovery, validation
  and proof engine relates to ProjectDiscovery's template-based scanner, and
  how HunterX integrates Nuclei into its orchestration workflow.
---

# HunterX vs Nuclei

[Nuclei](https://github.com/projectdiscovery/nuclei) is a fast,
template-based vulnerability scanner. HunterX is an AI-assisted vulnerability
discovery, validation and proof engine. They are **complementary**: HunterX
integrates Nuclei as a fully-supported tool in its orchestration layer.

## What Nuclei is good at

- Fast template-based checks across a large template library (CVEs,
  misconfigurations, exposures, web vulnerabilities).
- Simple, focused single-purpose scanning.

## What HunterX adds

- **Orchestration** — HunterX executes Nuclei with structured contracts,
  parses its JSON output into canonical observations and correlates them with
  other tools.
- **Validation and proof** — Nuclei findings become hypotheses that HunterX
  validates with evidence, and then engineers and replays proofs/PoCs.
- **Reasoning and correlation** — HunterX reasons over observations across the
  whole toolchain rather than treating each scanner result in isolation.
- **Report-ready output** — validated findings feed professional reports
  (Markdown, HTML, JSON, SARIF, PDF, package).

## Key differences

| Dimension | Nuclei | HunterX v7 |
|---|---|---|
| Primary model | Template-based scanning | AI-assisted discovery, validation & proof |
| Output | Candidate matches (JSON) | Validated findings + evidence + PoC + impact |
| Validation | Template match | Evidence-driven hypothesis validation |
| Proof / PoC | — | Proof contracts, replay, reproducibility |
| Reporting | JSON | Markdown, HTML, JSON, SARIF, PDF, package |
| Tool integration | Single-purpose | Orchestrates 92 security tools |

## Integration

In HunterX, Nuclei is **Integrated &middot; fully supported**: structured
execution, versioned parser and normalizer, and canonical observations. Nuclei
results are never raw verdicts — they pass the canonical pipeline
(`output → parser → normalizer → observation → correlation → validation →
proof`).

## Which to choose

- Use **Nuclei** directly when you need fast, focused template-based scanning.
- Use **HunterX** when you want the broader workflow: orchestrate many tools,
  validate findings with evidence, engineer and replay PoCs, and produce
  report-ready output.

Both are open source; HunterX integrates Nuclei rather than replacing it.

## Related

- [Tool Ecosystem](/tool-ecosystem/)
- [Comparisons](/comparisons/)
- [PoC & Validation](/poc-validation/)
