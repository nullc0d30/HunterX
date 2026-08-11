# 24 — Quality Assurance

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** Acceptance criteria, review checklists, architecture/security/performance reviews, change processes

---

## 1. Purpose

QA is the enforcement mechanism for the entire Bible. It defines what "done"
and "acceptable" mean, who reviews what, and how changes to ratified standards
occur. QA is a **gate**, not a report.

---

## 2. Acceptance Criteria

### 2.1 Mission Acceptance

A mission is accepted when (matching `12` expected-output contract):

- All planned phases completed (or explicitly degraded with recorded reason).
- Every finding above the profile's `evidence_threshold` has evidence refs.
- Findings deduplicated; canonical hashes valid.
- Reports generated in all required formats (`12` §7).
- Risk rollups computed per profile risk model.
- Audit trail complete (timeline, approvals, tool runs, AI decisions).
- No scope violations; any `VIOLATED` outcomes escalated and explained.
- Reproducibility: `plan_id` and mission `ai_seed` recorded.

### 2.2 Feature / Change Acceptance

- Meets the Definition of Done (`01` §9).
- Tests added/updated per `15`.
- Docs updated per `16`.
- No architecture violations (`04` §7, import-linter green).
- Security requirements satisfied (`13`).
- Performance within budget (`14`) for the touched paths.

---

## 3. Team Review Checklist (PR-level)

- [ ] Purpose clear; issue linked.
- [ ] CI green (lint, format, types, architecture, tests, coverage, security).
- [ ] Tests for new behavior + regression test for fixes.
- [ ] Goldens updated deliberately where parsers/schema changed.
- [ ] Docs updated (Bible refs, README, CLI/API where applicable).
- [ ] No secrets / placeholders / TODOs in shipped paths.
- [ ] Logging/tracing/audit coverage for new operations.
- [ ] Error handling: typed exceptions, safe messages, codes registered.
- [ ] Naming, typing, style per `04`.
- [ ] CHANGELOG entry added.

---

## 4. Roles & Responsibilities

| Role | Authority |
|------|-----------|
| Contributor | Implements, tests, documents |
| Reviewer | Approves PR (≥1; 2 for core/arch/security) |
| Architecture Owner | Approves architecture-relevant changes, ADRs, folder/schema changes |
| Security Reviewer | Approves security-sensitive changes, sandbox/permissions/secrets |
| Performance Owner | Approves perf-relevant changes; owns benchmarks |
| Release Manager | Enforces SemVer, release process (`23`) |
| Schema Owner | Approves Unified Security Schema changes |

---

## 5. Review Checklists

### 5.1 Architecture Review

- Dependency rule respected; domain has no framework imports.
- Ports/adapters correct; no bypass of abstraction (e.g., direct AI SDK use).
- Event/message usage instead of tight coupling.
- New component fits `03` structure and ownership.
- Scalability/air-gap/distribution considered (`25`).
- ADR recorded for notable decisions.

### 5.2 Security Review

- Sandbox: isolation, limits, scope envelope enforced.
- Permissions: deny-by-default; least privilege.
- Secrets: never in logs/prompts/reports; vault-backed.
- Tool output treated as untrusted data.
- Input validation at all boundaries; injection-resistant.
- AuthN/AuthZ: RBAC, scoped access, no bypass.
- Audit events emitted for sensitive operations.
- Supply chain: deps pinned/scanned; signatures verified.

### 5.3 Performance Review

- Benchmarks added/updated for hot paths; no >10% regression.
- Memory bounded; streaming used for large data.
- Query plans reviewed for new DB access; indexes added.
- Concurrency limits and rate limits configured.
- No N+1, no unbounded caches.

### 5.4 Documentation Review

- Behavior change ⇒ doc change present.
- Diagrams accurate; diagrams render.
- Examples sanitized and tested.
- Versioning/status headers correct.

---

## 6. Architecture Change Process (ADR)

Any change to: layering, folder structure, core contracts, SDK ABI, deployment
topologies, or cross-cutting behavior requires an **Architecture Decision Record**:

1. Author ADR (context, decision, consequences, alternatives).
2. Architecture Owner + at least one senior reviewer approve.
3. ADR referenced from the changed docs.
4. Implemented only after approval (no code-first for architectural change).

ADR register: `docs/ADR/` (or `docs/bible/` appendix); numbered sequentially.

---

## 7. Schema Change Process

Any change to `08` or `09` schema:

| Severity | Process |
|----------|---------|
| **Patch** (additive optional field, docs) | Normal PR + Schema Owner approval |
| **Minor** (new enum value, new optional entity) | PR + Schema Owner + API compatibility check |
| **Major** (breaking, removal, type change) | ADR + migration plan + dual-write/backfill + versioned rollout (`09` §13) |

Schema changes always bump the schema version and update goldens.

---

## 8. Performance Review Triggers

- Any change to: parser, normalizer, store, engine, cache, or hot API path.
- New indexes/migrations.
- New AI prompt classes (token budget).
- New tool profiles.

---

## 9. Release QA Gates

Before any release (`23` §8):

- [ ] Full CI + acceptance on sandboxed targets.
- [ ] Performance smoke passed.
- [ ] Security suite passed; dependency scan clean.
- [ ] Changelog complete; SemVer consistent.
- [ ] Docs site rebuilt; API docs current.
- [ ] SBOM generated; images signed.

---

## 10. Continuous Improvement

- QA metrics tracked: test coverage, CI failure rate, security test count,
  benchmark regressions, mean time to merge.
- Retrospective after incidents; lessons ratified into standards.
- Bible amendments go through the ADR process and are versioned.

---

## 11. References

- `01 - Vision.md` §9 (Definition of Done)
- `15 - Testing Standards.md` (test gates)
- `23 - Development Workflow.md` (PR/release process)
- `04 - Coding Standards.md` §14 (review gates)
