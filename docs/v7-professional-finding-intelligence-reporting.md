# HunterX v7 — Professional Finding Intelligence & Reporting

Sprint 029 (Wave 14) capability. This document describes the professional
reporting architecture: how HunterX transforms a **validated finding** plus
**evidence**, **proof**, **impact**, **provenance**, **target intelligence**
and **correlation** into a professional security report package.

> The reporting engine is not a text generator. It is an evidence-backed
> security intelligence and reporting system. AI writes the explanation;
> HunterX evidence determines the truth.

---

## Core Principle

The reporting system **never manufactures facts**. Every report statement is
traceable to an observation, evidence, validation, proof, impact assessment,
tool result, target intelligence or explicit analyst reasoning. AI-generated
prose is presentation; evidence remains authoritative.

A report is never `READY_FOR_SUBMISSION` while:

- a QA check fails,
- an unsupported high-impact claim is open,
- or a secret/PII leak is detected.

---

## Architecture Overview

```
 validated finding
        │
        ▼
 FindingIntelligence (aggregate)
        │
        ├─ classification  (CWE / OWASP / CAPEC / CVE / CVSS / ATT&CK)
        ├─ severity        (evidence-backed, never class-derived)
        ├─ quality         (report defensibility, distinct from confidence)
        ├─ priority        (P0–P4, distinct from severity)
        ├─ reportability   (REPORTABLE / INCOMPLETE / DISPUTED / ...)
        ├─ business impact (evidence or analyst reasoning)
        ├─ asset criticality (target intelligence integration)
        ├─ attack-path relationships
        ├─ root cause
        ├─ evidence bundle (immutable, integrity-hashed)
        ├─ timeline        (from actual events only)
        ├─ tool provenance + source reliability
        ├─ remediation + retest plans
        └─ claims + QA + redaction
        │
        ▼
 ReportDocument (versioned, immutable)
        │
        ├─ Markdown / HTML / JSON / SARIF / PDF / package
        └─ report lifecycle (DRAFT → ... → READY_FOR_SUBMISSION → CLOSED)
```

### Layer separation

| Layer | Modules | Responsibility |
|---|---|---|
| domain | `hunterx.domain.reporting` | pure models + engines (no I/O) |
| ports | `hunterx.domain.ports.reporting` | exporter contract |
| application | `hunterx.application.professional_reporting` | use-case orchestration |
| reporting adapter | `hunterx.reporting` | renderers + exporter adapter |
| TIDB | `domain.entities.tidb.reporting_intelligence` | system-of-record |

Dependency direction points inward: the application service depends on the
domain port, never on the concrete renderers.

---

## Finding Intelligence

`FindingIntelligence` is the canonical aggregate that extends (never
duplicates) the `Finding` entity. It aggregates:

- finding, evidence, validation, proof, reproduction
- impact, severity, confidence, quality
- target / asset / technology intelligence
- attack-path relationships, root cause, historical observations
- tool provenance, timestamps, scope
- deduplication state and report state

It is built by `analyze_finding` and drives every downstream engine.

## Report Lifecycle

Explicit transitions only (`ReportStateMachine`):

```
DRAFT → EVIDENCE_REVIEW → ANALYSIS_COMPLETE → REPORTABLE → REPORT_GENERATED
  → QA_REQUIRED → QA_PASSED / QA_FAILED → READY_FOR_SUBMISSION → SUBMITTED
  → REOPENED / CLOSED
```

`READY_FOR_SUBMISSION` requires: QA passed, no unsupported high-impact claim,
and redaction applied.

## Reportability Engine

`ReportabilityEngine` evaluates scope, validation, proof, reproducibility,
impact, severity, confidence, evidence completeness, duplicate status,
false-positive status, required metadata and policy. Verdicts:
`REPORTABLE`, `INCOMPLETE`, `DISPUTED`, `DUPLICATE`, `OUT_OF_SCOPE`,
`NOT_ACTIONABLE`.

## Finding Quality Engine

`FindingQualityEngine` scores report defensibility across 12 weighted factors
(evidence, validation, proof, reproducibility, impact, scope/asset/root-cause
certainty, freshness, tool reliability, contradictions, report completeness).
Produces `quality_score`, `quality_grade` (A–F) and `quality_explanation`.
Quality answers *"how strong and defensible is this report?"* — it does not
replace vulnerability confidence.

## Severity Engine

`SeverityAssessmentEngine` derives severity from evidence-backed impact
dimensions, exploitability evidence, proof replay, confidence, scope, asset
criticality and business context. `critical` requires direct evidence of
high-impact, exploitable impact — a class name alone can never produce it.
Findings without a replayed proof and confidence below 0.9 are capped below
high.

## CVSS

CVSS v3.1 and v4.0 vectors are parsed without inventing missing metrics
(reusing `hunterx.domain.vulnerability.cvss`). The assessment stores the
vector, base score, severity, optional environmental score, source and
explanation. Environmental values are never fabricated.

## CWE / OWASP / ATT&CK

`ClassificationEngine` maps findings onto CWE (multiple mappings supported),
OWASP Top 10 / API Top 10, CAPEC, referenced CVEs and MITRE ATT&CK. Every
mapping carries an explicit confidence and rationale. ATT&CK mappings are
only produced where a technique genuinely applies and never imply that the
mapped stage was achieved. CVEs are only attached when the finding evidence
references them.

## Business Impact

`BusinessImpact` supports data exposure, credential exposure, account
takeover, privilege escalation, unauthorized access, remote code execution,
cloud resource access, financial impact, business-process manipulation,
availability impact and reputation/security-boundary impact. Every claim must
have evidence or explicit analyst reasoning.

## Root Cause & Attack Paths

Reports distinguish **symptom**, **vulnerability**, **root cause** and
**impact**. Multiple endpoints sharing one defect are correlated under one
`root_cause_id` with multiple affected locations, without collapsing
evidence. Attack paths are explained only where evidence supports them; a
theoretical path never implies compromise.

## Evidence Bundle & Integrity

`EvidenceBundleBuilder` assembles an immutable bundle referencing raw
observations, requests, responses, headers, callbacks, tool output,
validation results, PoCs and replay results, each with a SHA-256 content hash
and full provenance. `verify_integrity` recomputes the bundle hash and detects
altered evidence.

## Timeline & Tool Provenance

The finding timeline is built strictly from actual persisted events and
timestamps (`FindingTimelineBuilder` rejects empty timestamps). Every
tool-derived fact preserves tool, version, command/configuration reference,
execution id, timestamp, target, scope, result reference and normalization
version.

## Source Reliability

`SourceReliabilityModelBuilder` classifies sources (direct observation,
validated replay, controlled callback, tool signature, historical archive,
external intelligence, AI inference, analyst annotation) into ordered
reliability ranks. Direct validated evidence always outranks AI inference.

## AI Reporting

AI may assist with titles, executive summaries, technical explanations,
root-cause explanations, impact narratives, remediation wording, attack-path
narratives, report organization and language quality. AI must never invent
evidence, affected assets, impact, PoCs, CVEs, CVSS values, remediation
validation, change proof state, change scope or override evidence conflicts.

## Claims

`ClaimExtractor` + `ClaimVerifier` extract material claims from the structured
document and verify them against the verified evidence index. Unsupported
high-impact claims are `BLOCKED`; QA fails and the report cannot become
`READY_FOR_SUBMISSION`.

## Report QA

`ReportQAEngine` checks: missing fields, unsupported claims, missing evidence,
missing PoC where required, invalid severity, invalid CVSS, invalid CWE,
scope issues, secret leakage, PII leakage, contradictions, duplicate findings,
broken references, stale evidence, unsupported impact and AI-hallucination
indicators. Each check returns PASS / FAIL / WARN.

## Redaction

`ReportRedactor` redacts passwords, API keys, tokens, cookies, session
identifiers, private keys, unnecessary PII and internal secrets while
preserving reproduction utility. Evidence remains internally referenceable —
only the report output is redacted.

## Templates

`ReportTemplateEngine` provides data-driven templates (Bug Bounty, Pentest,
Executive Pentest, Technical Pentest, Web App Pentest, API Pentest, Cloud
Assessment, Red Team, Vulnerability Disclosure, Research). Report structure is
defined in data, never hardcoded into business logic.

## Exports

`report_renderers` render a `ReportDocument` into Markdown, HTML, JSON, SARIF
2.1.0, PDF (standard-library minimal writer) and the structured HunterX
Finding Package. SARIF preserves HunterX-specific evidence references in
result properties. The architecture supports future DOCX, STIX, CSV and custom
templates.

## Remediation & Retest

`RemediationEngine` produces immediate mitigations, short-term fixes,
long-term architectural fixes, configuration changes, code-level remediation,
monitoring and validation recommendations tied to the actual root cause.
`RetestPlanEngine` produces what must change, endpoints to test, behaviors
that must disappear, proofs that must fail, evidence to collect and acceptance
criteria. Remediation validation supports
`OPEN → REMEDIATION_IN_PROGRESS → RETEST_REQUIRED → RETESTING → FIX_VERIFIED /
FIX_FAILED → REOPENED / CLOSED`.

## Versioning & Reproducibility

Reports are immutable and versioned (`ReportVersion`). A new generation never
overwrites a historical report. Generation references a consistent evidence
snapshot. Identical snapshots + template + generator produce deterministic
structured output.

## Security

The capability is hardened against report/HTML/Markdown/SARIF injection,
secret and PII leakage, cross-target and cross-mission evidence leakage,
malicious evidence/tool output, AI-hallucinated claims, template injection,
path traversal and report tampering.

## Persistence

TIDB entities and ORM models (Alembic migration `b2e3f5a7c9d1`) persist report
metadata, report versions, templates and template versions, claim records, QA
results, evidence snapshots, report packages, remediation plans, retest plans
and submission state. No uncontrolled schema shortcuts.

## Events

Typed `report.*` events: `report.created`, `report.updated`,
`report.qa.started`, `report.qa.passed`, `report.qa.failed`,
`report.generated`, `report.exported`, `report.submission_ready`,
`report.retest.started`, `report.retest.completed`, `report.closed`,
`report.reopened`. All carry mission/target/finding/report ids, correlation
id, timestamp and provenance.

## API & CLI

Application services are exposed through the `ProfessionalReportingService`;
`/reports` API routes and the `hunterx report <subcommand>` CLI group cover
analyze/classify/severity/quality/priority/reportability/evidence/timeline/
remediation/retest/generate/validate/export/sarif and report management.

## Extension Model

- **New template kinds**: add sections in `hunterx/domain/reporting/templates.py`.
- **New classification mappings**: extend the catalogs in `classification.py`.
- **New remediation guidance**: extend the catalog in `remediation.py`.
- **New export formats**: add a renderer in `reporting/report_renderers.py` and
  register it in the `render` dispatcher.
- **AI providers**: implement `AIPort`; AI output remains advisory and is
  always gated by claim verification and QA.
