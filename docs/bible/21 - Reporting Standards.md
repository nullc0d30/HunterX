# 21 — Reporting Standards

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** Reporting Engine, renderers, templates, exports, evidence packages

---

## 1. Purpose

Reporting transforms **canonical, evidence-backed findings** into professional
artifacts for technical teams, executives, compliance reviewers, and
integrators. Reports are derived **only** from the Unified Security Schema
(`08`) — renderers never touch raw findings directly.

---

## 2. Report Views

| View | Audience | Content |
|------|----------|---------|
| **Technical** | Pentester/engineer | Full detail: every finding, evidence, reproduction, affected assets |
| **Executive** | Management | Summary, risk posture, top findings, remediation priorities |
| **Evidence Package** | Reviewer | Raw evidence: screenshots, requests/responses, logs, payloads (checksummed) |
| **Timeline** | Reviewer/auditor | Chronological mission timeline (phases, findings, approvals, tool runs) |
| **Compliance** | Compliance | Mapping to frameworks (OWASP, PCI-DSS, MITRE) |

---

## 3. Report Data Model

A report is assembled from `ReportBundle`:

- `mission` summary (scope, dates, status).
- `assets` inventory (canonical, deduplicated).
- `findings` (severity-ordered, correlated, deduplicated, with evidence refs).
- `risk` rollups (per asset, per domain, mission total).
- `timeline` entries.
- `compliance` mappings.
- `metadata` (template version, generator version, generated_at, content_hash).

Every report is **deterministic**: same mission state + same template version =
same bytes (up to embedded dynamic timestamps, which are pinned in headers).

---

## 4. Export Formats

| Format | Use | Notes |
|--------|-----|-------|
| JSON | Machine consumers, API, re-import | Canonical; includes full USS payload |
| Markdown | Docs, Git, quick review | Human-readable, portable |
| HTML | Web review, dashboards | Self-contained; no external assets |
| PDF | Client delivery | Paginated, branded, cross-platform |
| SARIF | IDE/CI integration | Findings mapped to SARIF 2.1.0 schema |
| CSV (future) | Spreadsheet consumption | Flat finding table |

- JSON is the **source of truth** for format fidelity; other formats derive from it.
- SARIF mapping: rule = finding category; level = severity; location = primary
  affected asset; `relatedLocations` = evidence endpoints; `partialFingerprints`
  = canonical finding hash; `properties` = provenance + CWE/CVE refs.

---

## 5. Evidence Package

- Bundles: screenshots, raw HTTP request/response pairs, logs, tool raw
  outputs (within retention), payloads used, verification transcripts.
- Each artifact records: object key, SHA-256, captured_at, source tool/step,
  redaction status.
- Package is a **checksummed archive** (zip with a manifest.json + per-file
  hashes) so reviewers can verify integrity.
- PII and secrets are redacted before packaging (masking at export boundary).

---

## 6. Timeline Report

Renders `TimelineEntry` sequence with:

- Phase/step boundaries.
- Finding lifecycle (new → confirmed → reported).
- Approvals and scope decisions.
- Tool runs (tool, target, duration, outcome).
- AI decisions (draft/triage provenance).
- Operator actions.

Used for auditability and client trust.

---

## 7. Compliance Mapping

| Framework | Mapping source |
|-----------|----------------|
| OWASP Top 10 | finding category → A1..A10 |
| MITRE ATT&CK | CVE/finding → technique |
| PCI-DSS | finding category → requirement |
| ISO 27001 / NIST CSF | finding class → control family |
| (extensible) | compliance mapping plugin (`05`) |

Mappings are **explicit and reviewed**; never LLM-guessed for compliance
reports (deterministic mapping files; AI drafting optional and labeled).

---

## 8. Rendering Pipeline

```
ReportService.request(mission, views, formats)
  → assemble ReportBundle (from TIDB + graph + evidence refs)
  → for each view: apply template (versioned)
  → for each format: render (deterministic)
  → compute content_hash
  → store artifacts in object store + report records
  → emit report.generated event → notify subscribers
```

- Long renders run as async jobs (`20` §6).
- Renderer pool bounded (PDF/image-heavy) per `14` §8.

---

## 9. Templates

- Templates are versioned; a report records `template_version`.
- Template changes: additive/minor = minor template bump; structural change =
  major (older reports remain reproducible).
- Report templates support: HTML/CSS (HTML+PDF), Jinja (MD/HTML), JSON schema
  (JSON), SARIF schema.

---

## 10. Branding & Internationalization

- Branding (logo, client name) injected at render; never baked into data.
- Locale/templates: report text templated; i18n supported for UI-facing
  formats (MD/HTML); JSON/SARIF always canonical English keys.

---

## 11. Versioning & Retention of Reports

- Reports are immutable artifacts: a new generation creates new report records;
  old ones retained per retention policy (`09` §8).
- `content_hash` enables deduplication and verification.
- Re-generate vs re-render: regenerate = re-run analysis (new data);
  re-render = same data, new format/template.

---

## 12. Security of Reports

- Access control: report visibility per engagement/RBAC (`13` §4).
- Redaction of secrets/PII at packaging boundary (masking + tests).
- PDF: metadata sanitized (no internal paths/emails unless intended).
- HTML: self-contained, no external fetch; CSP embedded.
- Signing (optional): report artifact signature for delivery integrity.

---

## 13. Reporting Quality Gates

- All findings in technical report reference evidence (`evidence_refs`).
- Executive report excludes raw payloads; summarizes with risk posture.
- No secrets in any format — verified by security tests (`15` §6).
- Mandatory formats per mission profile honored (`12` §7).

---

## 14. References

- `08 - Unified Security Schema.md` (report entities)
- `12 - Mission Profiles.md` (expected output contract)
- `13 - Security Standards.md` (redaction, access control)
- `15 - Testing Standards.md` (report golden tests)
