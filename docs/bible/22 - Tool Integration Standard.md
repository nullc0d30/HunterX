# 22 — Tool Integration Standard

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** Every integrated tool; checklist for `tools/<tool-id>/`

---

## 1. Definition

A tool is **integrated** into HunterX only when the complete integration
package described in this document exists, passes all gates, and is merged.
A "half-integrated" tool is not an integration — it is a defect.

---

## 2. Mandatory Components

Every integrated tool MUST contain **all** of the following:

| # | Component | Location | Specification |
|---|-----------|----------|---------------|
| 1 | Knowledge File | `tools/<id>/knowledge.yaml` | `07 - Tool Knowledge Base Specification.md` |
| 2 | Adapter | `tools/<id>/adapter.py` | `06 - Tool Adapter SDK.md` |
| 3 | Parser | `tools/<id>/parser.py` | `06` §3; streamed |
| 4 | Normalizer | `tools/<id>/normalizer.py` | `06` §3; canonical mapping |
| 5 | Workflow Rules | `tools/<id>/workflows.yaml` | `07` §14 |
| 6 | Mission Rules | `tools/<id>/mission_rules.yaml` | `07` §15 |
| 7 | Target DB Mapping | inside normalizer + knowledge | `08` entities |
| 8 | AI Rules | `tools/<id>/ai_rules.yaml` | `07` §16, `11` |
| 9 | Tests | `tools/<id>/tests/` | `15` |
| 10 | Documentation | `tools/<id>/README.md` | `16` |

---

## 3. Component Contracts (summary)

### 3.1 Knowledge File (`knowledge.yaml`)

- Validates against `config/knowledge.schema.yaml`.
- Declares: metadata, capabilities, CLI model (safe argv), profiles (≥
  `fast/thorough/stealth/quiet`), modes, input/output contracts, dependencies,
  error mapping, performance, workflow position, mission rules, AI rules.
- No secrets; no shell templates.

### 3.2 Adapter (`adapter.py`)

- Implements at least one contract from `06` (`ScannerAdapter`, `CrawlerAdapter`,
  `EnumeratorAdapter`, `AnalyzerAdapter`, `ReporterAdapter`, `ValidationAdapter`).
- Implemented methods: `execute`, `parse`, `normalize`, `validate`, `healthcheck`,
  `capabilities`, `describe`.
- All execution through the sandboxed executor; never direct subprocess.

### 3.3 Parser (`parser.py`)

- Streams output (iterator); no unbounded buffering.
- Declares accepted formats (from knowledge `output.formats`).
- Never evaluates input; declarative only.

### 3.4 Normalizer (`normalizer.py`)

- Maps parsed items → canonical `CanonicalEvent`s (`08` §4).
- Applies canonicalization (FQDN, CIDR, dedup keys, severity mapping).
- Uses `08` entity/event types; no free-form dicts.

### 3.5 Workflow Rules (`workflows.yaml`)

- Phases where the tool participates.
- Prerequisites/produces (which canonical events feed which steps).
- Typical sequence position and blocking semantics.
- See `07` §14 and `10`.

### 3.6 Mission Rules (`mission_rules.yaml`)

- Applicable mission profiles (`12`).
- Per-mission overrides (modes, approval).
- Approval level (auto/operator/destructive-approval).
- Auth profiles the tool accepts.
- See `07` §15.

### 3.7 Target Database Mapping

- Every produced entity maps to `08` tables and graph edges (`09` §10).
- Every consumed input type is declared in knowledge `inputs.accepts`.
- No entity invented outside USS (schema change required otherwise).

### 3.8 AI Rules (`ai_rules.yaml`)

- `allowed` (bool) and `purposes`/`disallowed` lists.
- `grounding` context requirements and token budget.
- Output usage permissions.
- Hallucination warnings.
- See `07` §16 and `11`.

### 3.9 Tests

Minimum test set:

- **Adapter unit:** execute with canned outputs; asserts ToolResult fields.
- **Parser unit:** parse fixtures (valid, malformed, empty) → ParsedItems.
- **Normalizer unit:** canonical events match expected `08` mapping.
- **Golden:** `data/golden/tools/<id>/` input→expected events.
- **Integration:** run real binary (marked `@pytest.mark.tools`), assert end-to-end.
- **Security:** overscope argv rejected; injection neutralized; no secret leak;
  prompt-injection on poisoned output handled.
- Coverage: ≥ 80% of parser+normalizer+adapter (`15` §9).

### 3.10 Documentation (`README.md`)

- What the tool does, installation, profiles, modes, example runs, limitations.
- How findings map into USS; how AI may use results.
- Rollback/cleanup notes for side effects (`17` §6).

---

## 4. Workflow for Adding a Tool

```
proposal (tool + justification + capability gap)
  → knowledge.yaml draft
  → adapter/parser/normalizer implementation
  → fixtures + goldens
  → integration on sandboxed target
  → security tests
  → docs
  → PR → CI gates → Architecture + Security review
  → merge → registry index update (tools/index.yaml)
```

---

## 5. Registry Index

`tools/index.yaml` maintains the shared capability vocabulary and maps:

```
capabilities:
  - id: vulnerability-scan
    tools: [nuclei, nikto, openvas]
  - id: subdomain-enum
    tools: [subfinder, amass]
```

- New capability ids require a review (shared vocabulary stability).
- Tool removal: deprecate in index, quarantine adapters, honor retention.

---

## 6. Quality Gates (fail = no merge)

- `knowledge.yaml` schema-valid.
- Adapter passes `06` contract tests (abstract base test suite).
- Parser/normalizer golden tests pass.
- Real-binary integration passes or is explicitly skipped with justification.
- Security suite passes.
- Coverage thresholds met.
- Docs complete per `16`.
- No secrets, no shell templates, no direct subprocess.

---

## 7. Tool Maintenance

- Versioned: `tool_versions` range in knowledge; adapter SemVer independent.
- Upstream changes: re-run golden regeneration, bump `tool_versions`, re-test.
- Deprecation: mark `deprecated: true`, warn on use, remove per retention policy.
- Health: `hunterx tool health` monitors availability; outages degrade
  gracefully (`17` §7).

---

## 8. References

- `06 - Tool Adapter SDK.md` — adapter contracts
- `07 - Tool Knowledge Base Specification.md` — knowledge file
- `08 - Unified Security Schema.md` — canonical mapping
- `15 - Testing Standards.md` — test requirements
- `17 - Error Handling Standards.md` — failure handling for tools
