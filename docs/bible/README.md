# HunterX Development Bible

**Status:** Ratified corpus
**Version:** 1.0.0
**Owner:** HunterX Architecture Council

The **HunterX Development Bible** is the official engineering foundation and
single source of truth for every HunterX sprint. All implementation MUST comply
with these documents. No placeholders, no TODOs, no implementation code — this
is the specification of record.

---

## How to Use This Bible

1. **New contributors:** read `01 - Vision.md`, `02 - Architecture.md`,
   `04 - Coding Standards.md`, and `24 - Quality Assurance.md` first.
2. **Building a tool integration:** follow `22 - Tool Integration Standard.md`
   (which references `06`, `07`, and `15`).
3. **Writing a plugin:** follow `05 - Plugin SDK Specification.md`.
4. **Changing behavior:** update the affected docs in the same PR
   (`23 - Development Workflow.md`, `24 - Quality Assurance.md`).
5. **Growing the platform:** `25 - Future Expansion.md` guarantees the Core
   stays stable while tools, plugins, missions, and deployments expand.

---

## Document Index

| # | Document | Summary |
|---|----------|---------|
| 01 | [Vision](01%20-%20Vision.md) | Mission, goals, scope, non-goals, supported assessment types, philosophy |
| 02 | [Architecture](02%20-%20Architecture.md) | Full system design, subsystem contracts, C4 diagrams, ADRs |
| 03 | [Folder Structure](03%20-%20Folder%20Structure.md) | Complete repository hierarchy with dependency rules |
| 04 | [Coding Standards](04%20-%20Coding%20Standards.md) | Python standards: typing, naming, DI, SOLID, async, thread safety |
| 05 | [Plugin SDK Specification](05%20-%20Plugin%20SDK%20Specification.md) | Plugin lifecycle, manifest, permissions, versioning, security |
| 06 | [Tool Adapter SDK](06%20-%20Tool%20Adapter%20SDK.md) | Adapter contracts: Base, Scanner, Crawler, Enumerator, Analyzer, Reporter, Validation |
| 07 | [Tool Knowledge Base Specification](07%20-%20Tool%20Knowledge%20Base%20Specification.md) | Per-tool knowledge file contract |
| 08 | [Unified Security Schema](08%20-%20Unified%20Security%20Schema.md) | Canonical entities, events, severity/confidence models |
| 09 | [Database Design](09%20-%20Database%20Design.md) | TIDB, Knowledge Graph, ER, indexes, history, retention, caching |
| 10 | [Workflow Engine](10%20-%20Workflow%20Engine.md) | DAG execution, dependencies, retries, checkpoints, recovery |
| 11 | [AI Standards](11%20-%20AI%20Standards.md) | AI role, prompts, validation, confidence/risk, learning, safety |
| 12 | [Mission Profiles](12%20-%20Mission%20Profiles.md) | All 12 mission types: workflow, tools, outputs, risk models |
| 13 | [Security Standards](13%20-%20Security%20Standards.md) | Sandbox, permissions, secrets, isolation, supply chain, audit |
| 14 | [Performance Standards](14%20-%20Performance%20Standards.md) | Memory, CPU, scaling, caching, large-target support |
| 15 | [Testing Standards](15%20-%20Testing%20Standards.md) | Unit→acceptance pyramid, golden sets, coverage, CI |
| 16 | [Documentation Standards](16%20-%20Documentation%20Standards.md) | Markdown, diagrams (Mermaid), API docs, versioning |
| 17 | [Error Handling Standards](17%20-%20Error%20Handling%20Standards.md) | Taxonomy, retries, rollback, degradation, recovery |
| 18 | [Logging Standards](18%20-%20Logging%20Standards.md) | JSON logging, metrics, tracing, audit, performance logs |
| 19 | [CLI Standards](19%20-%20CLI%20Standards.md) | Commands, flags, profiles, formatting, errors, autocomplete |
| 20 | [REST API Standards](20%20-%20REST%20API%20Standards.md) | Auth, schemas, pagination, errors, versioning, security |
| 21 | [Reporting Standards](21%20-%20Reporting%20Standards.md) | Views, exports (JSON/MD/HTML/PDF/SARIF), evidence packages |
| 22 | [Tool Integration Standard](22%20-%20Tool%20Integration%20Standard.md) | Full checklist for every integrated tool |
| 23 | [Development Workflow](23%20-%20Development%20Workflow.md) | Git flow, branches, code review, CI/CD, release, SemVer |
| 24 | [Quality Assurance](24%20-%20Quality%20Assurance.md) | Acceptance criteria, review checklists, change processes |
| 25 | [Future Expansion](25%20-%20Future%20Expansion.md) | Unlimited tools/plugins, distributed execution, multi-agent AI |

---

## Binding Status

- **Ratified** — must be followed; changes via the ADR / Schema Change process
  (`24 - Quality Assurance.md` §6–§7).
- A conflict between docs is resolved in this order: `01` (philosophy) →
  `02` (architecture) → the specific domain doc → implementation decisions
  recorded as an ADR.

---

## Version & Changelog

| Version | Date | Change |
|---------|------|--------|
| 1.0.0 | 2026-08-05 | Initial ratification of the complete 25-document corpus |

---

## Related Project Documentation

- `docs/ARCHITECTURE.md`, `docs/AGENTS.md` — current implementation notes
  (superseded by this Bible where they conflict; migration tracked as
  engineering work).
- `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md` — project-level docs.
