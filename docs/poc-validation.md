---
layout: default
title: PoC & Validation — HunterX v7 Proof Engine
keywords: PoC generation, proof of concept security, vulnerability validation, proof engine, vulnerability proof, PoC validation, reproducible findings, evidence-driven confidence, impact assessment, vulnerability verification
description: >-
  How HunterX v7 validates vulnerabilities and engineers proofs: the Proof &
  PoC Validation Engine turns hypotheses into validated findings with
  evidence, minimal safe PoCs, replay, reproducibility, impact and
  evidence-driven confidence.
---

# PoC & Validation

HunterX treats **proof as part of vulnerability validation**. The v7 Proof &
PoC Validation Engine transforms a validated hypothesis into a report-ready
finding:

```
HYPOTHESIS → PROOF CONTRACT → REQUIRED EVIDENCE → MINIMAL PROOF STRATEGY →
PROOF CONSTRUCTION → SAFETY VALIDATION → SCOPE VALIDATION → EXECUTION →
REPLAY → EVIDENCE EVALUATION → IMPACT → CONFIDENCE → VALIDATED FINDING →
REPRODUCTION PACKAGE → REPORT
```

A vulnerability **detection is not a validated finding**. The engine maintains
the distinction:

```
DETECTED → SUSPECTED → VALIDATING → VALIDATED → PROVEN → CONFIRMED → REPORT_READY
                                            ↘ FALSE_POSITIVE
                                            ↘ INCONCLUSIVE
```

## Proof Contracts

Every supported vulnerability class has a deterministic **proof contract** that
defines preconditions, allowed and forbidden actions, required evidence,
expected result, failure and inconclusive conditions, replay requirements,
impact requirements, minimum confidence and whether confirmation is permitted.

The built-in contract registry covers: SQL/NoSQL injection, XSS, SSRF, path
traversal / LFI, file inclusion, broken access control (IDOR / BOLA), API
authentication and authorization, authentication, open redirect, CORS,
sensitive information exposure, security misconfiguration, dependency
vulnerabilities, known vulnerable components, cloud exposure, command-injection
indicators and **UNKNOWN_BEHAVIOR** (novel).

Per-class proof emphasis:

- **SQL injection** — baseline vs comparison request, behavioral difference,
  reproducible observation; prove injection, never extract data.
- **XSS** — input location, reflection context, encoding behavior, minimal
  proof markers.
- **SSRF** — controlled callback infrastructure, correlation token and
  timestamp match.
- **LFI / path traversal** — controlled proof resources, expected vs observed
  content.
- **IDOR / BOLA** — authorized test identities; Subject A vs Subject B on the
  same resource; no broad enumeration.
- **Authentication / authorization** — controlled identities, minimal requests,
  authorized vs unauthorized comparison.
- **Known vulnerable component** — component identity, version, vendor,
  affected range, exposure and independent evidence.

## Minimal Safe Proofs

PoCs are **structured artifacts** — request templates, differential tests and
configuration snapshots — never arbitrary executable scripts. Generation is
deterministic and safety-validated:

- inputs are bounded and refuse forbidden markers;
- secret-looking values are redacted before the PoC is returned;
- the expected result is derived deterministically from the proof inputs;
- PoCs are immutable — a changed PoC becomes a new version with lineage.

```
Scope → Authorization → Safety Policy → Proof Policy → Tool Capability → Execution
```

If any required condition is unknown, the engine **blocks** the action.

## Replay & Reproducibility

Each proof is replayed deterministically. A `ReplayVerdict` (`SUCCESS` /
`FAILED` / `INCONCLUSIVE` / `BLOCKED`) is computed by comparing observed vs
expected behavior, with input, configuration and evidence hashing.

Reproducibility is measured over **repeated** replays:

- `REPRODUCIBLE` — at least two successful replays with no failures.
- `PARTIAL` — mixed outcomes.
- `NOT_REPRODUCIBLE` — nothing reproduced.
- `NOT_ASSESSED` — no replay ran.

A single "executed once" is never "reproducible."

## Evidence-Driven Impact & Confidence

**Impact** is classified strictly from captured evidence — confidentiality,
integrity, availability, authorization, authentication, data exposure, account
impact, resource access, business logic, cloud resource exposure — never
inferred merely because a vulnerability class is normally severe.

**Confidence** is a versioned, weighted policy over named factors: detection
evidence, behavioral evidence, independent verification, impact evidence, PoC
reproducibility, evidence quality, scope certainty and target stability.
`CONFIRMED` can never be reached unless the proof contract permits confirmation.

## False Positives & Inconclusive

A PoC that fails **must not automatically create a false positive**. The engine
returns `INCONCLUSIVE` when the target changed, preconditions changed, WAF
behavior changed, the network was unstable, authentication state changed, the
tool failed or evidence was insufficient. `FALSE_POSITIVE` requires evidence
that the original hypothesis was incorrect.

## Novel / Unknown Behavior

For behavior that does not match a known signature, HunterX follows a
hypothesis-driven loop:

```
Unknown Behavior → Observation → Hypothesis → Experiment → Unexpected Result →
New Hypothesis → Minimal Proof Strategy → Replay → Evidence → Candidate Finding
```

A novel finding remains a **candidate** until sufficient evidence exists. This
is hypothesis-driven discovery and investigation of unknown or
application-specific behaviors — not a guarantee of autonomous zero-day
discovery.

## Report-Ready Findings

The final finding report answers: WHAT is vulnerable, WHERE, WHY, HOW it was
validated, WHAT evidence proves it, WHAT PoC demonstrates it, CAN the PoC be
reproduced, WHAT impact was demonstrated, WHAT confidence exists, WHAT
assumptions remain, WHAT tool produced the evidence, WHEN it was validated and
WHAT scope authorized the test.

A **ReproductionPackage** bundles the finding summary, affected asset,
preconditions, PoC, replay instructions, expected and observed results,
evidence references, impact evidence, tool information, validation timestamp,
scope and version information — suitable for authorized bug-bounty and pentest
reporting.

## Safety

The engine is **not a weaponization engine**. Data destruction, persistence,
credential dumping, malware deployment, reverse shells, lateral movement,
denial of service, resource exhaustion, mass data extraction, unrestricted
database extraction, table dumping, credential attacks and weaponized exploit
execution are **never** scheduled. Proof means demonstrating the vulnerability
with the minimum necessary interaction and impact.

For RCE specifically, proof emphasizes minimal-impact demonstration, evidence
of execution, and reproducibility — not destructive commands.

## Related

- [Vulnerability Proof & PoC (architecture)](/v7-vulnerability-proof-and-poc/)
- [Vulnerability Validation & Proof Orchestration](/v7-vulnerability-validation-proof-orchestration/)
- [Safe Vulnerability Validation](/v7-safe-vulnerability-validation/)
- [Professional Finding Intelligence & Reporting](/v7-professional-finding-intelligence-reporting/)
- [Tool Ecosystem](/tool-ecosystem/)
