---
layout: default
title: HunterX Security Pipeline
description: >-
  The HunterX security scanner pipeline: bandit, semgrep, gitleaks, pip-audit,
  safety and Trivy filesystem/image scans. Graceful degradation, finding
  classification, artifacts and CI wiring.
permalink: /v7-security-pipeline/
---

# HunterX Security Pipeline

**Status:** Ratified (Sprint 006.9)
**Version:** 1.0.0
**Owner:** HunterX Engineering Council

---

## 1. Purpose / Scope

This document describes `eng.security`, the pipeline that scans the HunterX
repository for security defects on every CI run. It covers the scanner
inventory, the graceful-degradation contract, finding classification, artifact
output, and how the pipeline plugs into the security quality gate
([v7-quality-gates.md](v7-quality-gates.md)).

The pipeline is invoked with:

```bash
python -m eng security            # human-readable summary
python -m eng security --json     # machine-readable report
```

The CI entry point is `security-tests.yml`; the aggregate result is also wired
into the blocking `ci.yml` job through the `security` quality gate.

---

## 2. Scanner Inventory

| Scanner | Target | Format | Purpose |
|---|---|---|---|
| bandit | `src/hunterx` | txt | Python static security analysis |
| semgrep | `src/` | JSON | Pattern-based SAST (`--config auto`) |
| gitleaks | repo | JSON | Secret / credential detection |
| pip-audit | `requirements.lock` | JSON | Known-vulnerability audit (PyPI OSV) |
| safety | `requirements.lock` | JSON | Known-vulnerability audit (Safety DB) |
| trivy-fs | repo tree | JSON | Vulnerabilities + secrets + misconfigurations |
| trivy-image | `nullc0d30/hunterx:latest` | JSON | Published-image HIGH/CRITICAL audit |

### Scanner invocation

```bash
bandit -r src/hunterx -f txt -o artifacts/security/bandit.txt -q
semgrep --config auto --json-output artifacts/security/semgrep.json src/
gitleaks detect --source . --report-format json --report-path artifacts/security/gitleaks.json --no-banner
pip-audit -r requirements.lock --disable-pip --format json -o artifacts/security/pip-audit.json
safety check -r requirements.lock --json -o artifacts/security/safety.json
trivy fs --scanners vuln,secret,misconfig --skip-dirs build,dist,reports,artifacts,payloads \
  --format json --output artifacts/security/trivy-fs.json --exit-code 1 .
trivy image --scanners vuln,secret --severity HIGH,CRITICAL \
  --format json --output artifacts/security/trivy-image.json --exit-code 1 nullc0d30/hunterx:latest
```

---

## 3. Graceful Degradation Contract

The pipeline MUST never fail a local or CI run merely because a scanner is
unavailable. Each scanner reports one of four statuses:

| Status | When |
|---|---|
| `pass` | Scanner ran with a zero exit code (no blocking findings). |
| `fail` | Scanner ran and reported findings (or a blocking error). |
| `error` | The executable exists but failed to start (exit 127). |
| `skipped` | The executable is not installed, or the scan subject is genuinely unavailable in this context. |

Skipped scans do not block the pipeline. This is what makes a bare local
environment usable and lets CI install the full toolchain without the pipeline
breaking on missing tools.

### Context-aware skipping

Some scans depend on artifacts that do not exist in every context. The container
image scan (`trivy-image`) is the canonical example: before the image is
published, Trivy reports "image not found". `SecurityScanner` supports
`skip_failures_containing`, a tuple of substrings; when a failed run's output
matches any of them, the scan is reported as **skipped** instead of failed:

```python
skip_failures_containing=("image not found", "unable to", "not found",
                          "failed to pull", "no such image")
```

---

## 4. Finding Classification

`eng.security._count_findings` extracts a best-effort finding count per scanner
output format:

- **bandit** — parses `Total issues: N`.
- **pip-audit** — parses the JSON array length (or `count`).
- **safety** — counts non-summary output lines.
- **trivy-fs / trivy-image** — `_count_trivy` sums `Vulnerabilities`,
  `Secrets` and `Misconfigurations` entries from the JSON report, with a
  line-based fallback for plain-text output.
- **semgrep / gitleaks** — non-zero exit is treated as findings in the modes
  used; the detail line carries the scanner's own message.

Every scan's raw combined output is persisted to `artifacts/security/<name>.txt`
(or the scanner's own JSON output path) for auditability.

---

## 5. Artifacts

```text
artifacts/security-report.json    <- aggregate: scans, failed, blocked, summary
artifacts/security/
  bandit.txt
  semgrep.json
  gitleaks.json
  pip-audit.json
  safety.json
  trivy-fs.json
  trivy-image.json
```

The aggregate report is uploaded by CI and consumed by the security quality
gate via `eng.security.to_gate_result`, which maps a blocked report to a
`GateStatus.FAIL`.

---

## 6. CI Wiring

- **`security-tests.yml`** runs `python -m eng security --json` on every PR and
  push and uploads `artifacts/security/` and `artifacts/security-report.json`.
- **`ci.yml`** includes the `security` gate in the mandatory blocking suite, so
  a scanner finding on the source or lock file blocks the merge.
- **`dependency-review.yml`** adds a second line of defense on pull requests,
  reviewing changed dependencies for licenses and known vulnerabilities.

---

## 7. Local Usage

The pipeline degrades to the tools you have installed. To run the full suite
locally, install the toolchain (see `pyproject.toml` `[project.optional-dependencies]`
dev extras) and the system scanners. Then:

```bash
python -m eng security
```

A clean run prints `7/7 scanners clean` (skipped scans count as clean).
