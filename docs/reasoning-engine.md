---
layout: default
title: Reasoning Engine — How HunterX Reasons About Vulnerabilities
keywords: reasoning engine, AI security reasoning, vulnerability reasoning, hypothesis driven security testing, evidence driven validation, security AI, explainable security findings
description: >-
  The HunterX v7 reasoning model: how the platform reasons over canonical
  observations, forms and tests hypotheses, validates with evidence, and
  distinguishes known signatures from novel or unknown behavior.
---

# Reasoning Engine

HunterX applies **AI-assisted reasoning** to security assessment. Its value is
not raw AI belief — it is a disciplined reasoning pipeline over canonical
observations that produces evidence-backed, explainable findings.

## Reasoning over observations

Raw tool output is never a verdict. HunterX applies the canonical pipeline:

```
tool output → parser → normalizer → canonical observation → correlation →
hypothesis → verification → evidence → proof → PoC → replay → finding
```

The reasoning engine works over **canonical observations** — normalized,
structured results from every tool in the orchestration layer — so reasoning
is grounded in what was actually observed.

## The reasoning workflow

```
DISCOVER → FINGERPRINT → REASON → HYPOTHESIZE → PROBE → VERIFY → PROVE →
POC → REPLAY → CORRELATE → REPORT
```

- **Hypothesize** — form security hypotheses from observed attack surface.
- **Probe** — run targeted, scope-aware tests through the toolchain.
- **Verify** — validate hypotheses with evidence and independent verification.
- **Prove** — engineer a minimal safe proof, replay it, confirm
  reproducibility.
- **Correlate** — connect observations, findings and evidence across tools and
  missions.

## Evidence-gated confidence

Confidence is a **versioned, weighted policy** over named factors:

- detection evidence
- behavioral evidence
- independent verification
- impact evidence
- PoC reproducibility
- evidence quality
- scope certainty
- target stability

A high AI confidence score is never a substitute for evidence.

## Known vs unknown behavior

For behavior that matches a known signature, HunterX applies the relevant
proof contract and validates deterministically. For behavior that does not
match a known signature, it follows a hypothesis-driven loop:

```
Unknown Behavior → Observation → Hypothesis → Experiment → Unexpected Result →
New Hypothesis → Minimal Proof Strategy → Replay → Evidence → Candidate Finding
```

Novel findings remain candidates until sufficient evidence exists. This is
hypothesis-driven discovery and investigation — not a claim of guaranteed
zero-day discovery.

## Explainability

Every validation verdict and finding transition records its reason. Confidence
calculations are weighted, auditable aggregates over named factors; reports
trace every statement to observation, evidence, validation, proof, impact,
tool result, target intelligence or explicit analyst reasoning.

## Related

- [PoC & Validation]({{ '/poc-validation/' | relative_url }}) — the proof engine
- [AI Penetration Testing]({{ '/ai-penetration-testing/' | relative_url }})
- [Vulnerability Validation & Proof Orchestration]({{ '/v7-vulnerability-validation-proof-orchestration/' | relative_url }})
- [Vulnerability Intelligence]({{ '/v7-vulnerability-intelligence/' | relative_url }})
- [Tool Ecosystem]({{ '/tool-ecosystem/' | relative_url }})
