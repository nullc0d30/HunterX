---
layout: default
title: HunterX v7 Full Toolchain Integration & Professional Tool Intelligence
description: >-
  Architecture and reference for the HunterX v7 Full Toolchain Integration
  (Sprint 031 / Wave 16): canonical toolchain vocabulary, knowledge contracts,
  capability vocabulary, selection, chain planning, fallbacks, structured
  execution, parsers/normalizers, evidence extraction, cross-tool correlation,
  security, resource controls, versioning, interfaces and testing.
permalink: /v7-full-toolchain-intelligence/
---

# HunterX v7 Full Toolchain Integration & Professional Tool Intelligence

**Status:** Ratified (Sprint 031 / Wave 16)
**Version:** 1.0.0
**Owner:** HunterX Architecture Council

---

## 1. Purpose / Scope

HunterX must be capable of *professionally* interacting with the complete
authorized offensive-security toolchain. This is **not** "run command and
capture stdout". It is:

```
UNDERSTAND TOOL
    → UNDERSTAND CAPABILITIES
    → UNDERSTAND REQUIREMENTS
    → SELECT TOOL
    → BUILD SAFE/SCOPED INVOCATION
    → EXECUTE → MONITOR → CAPTURE OUTPUT
    → PARSE → NORMALIZE → VALIDATE
    → EXTRACT OBSERVATIONS → EXTRACT EVIDENCE
    → CORRELATE → UPDATE TARGET MEMORY → UPDATE FINDINGS → UPDATE HYPOTHESES
    → SELECT NEXT ACTION
```

The critical principle: **HunterX understands tool semantics.** Every tool
integration defines *what the tool does, when to use it, when not to use it,
what inputs it accepts, what outputs it produces, what the output means and —
just as importantly — what the output does NOT prove.*

Sprint 031 does **not** add new vulnerability classes, new reporting, new
target-memory features, reverse engineering, malware analysis, new AI providers
or new attack techniques.

---

## 2. Canonical Toolchain Vocabulary (Domain)

The canonical domain model lives in `hunterx.domain.tool_intelligence` and
`hunterx.domain.tool_mastery`. Sprint 031 adds the full professional
vocabulary:

| Concept | Role |
|---|---|
| `ToolDefinition` | identity + category + version (via `ToolMetadata`) |
| `ToolCapability` | discrete, searchable capability a tool provides |
| `ToolKnowledge` | structured knowledge contract (inputs/outputs/args/modes/safety) |
| `ToolRequirement` | input, dependency, resource, safety and scope requirements |
| `ToolExecutionProfile` | full structured execution profile (execution_id, scope, refs) |
| `ToolExecutionResult` | structured result with artifact references, never a finding |
| `ToolObservation` | canonical observation (`CanonicalObservation`) |
| `ToolEvidence` | evidence classification (`EvidenceClass`) extracted from results |
| `ToolEvidenceConfidence` | confidence assessment combining reliability/completeness/… |
| `ToolHealthStats` / `ToolReliabilityStats` / `ToolAvailabilityReport` | health |
| `ToolVersion` | known/installed/constraint version facts |
| `ToolParser` / `ToolNormalizer` | versioned parser/normalizer contracts |
| `ToolStrategy` | primary/fallback/complementary/specialized strategy for a capability |
| `ToolResult` | unified result with `ToolOutputSemantics` |
| `ToolChain` / `ToolChainStep` / `ToolChainResult` | dependency-aware planning |

`ToolOutputSemantics` is the canonical semantic state of a result:
`FOUND`, `NOT_FOUND`, `UNKNOWN`, `ERROR`, `PARTIAL`, `TIMEOUT`, `BLOCKED`,
`RATE_LIMITED`, `UNSUPPORTED`, `INVALID_INPUT`. **Tool failure is never
reported as "target is safe".**

`EvidenceClass` classifies extracted evidence: `DIRECT`, `SUPPORTING`,
`CANDIDATE`, `NEGATIVE`, `EXECUTION`, `VALIDATION`, `METADATA`. Tool output
alone never automatically becomes a confirmed finding.

---

## 3. Capability Model & Vocabulary

Every tool declares capabilities. The approved toolchain maps onto the
capability model:

- `SUBDOMAIN_ENUMERATION` → canonical `subdomain-discovery`
- `PORT_SCANNING` → canonical `port-scanning`
- `HTTP_PROBING` → canonical `http-enumeration`
- `TECHNOLOGY_DETECTION`, `CRAWLING`, `URL_DISCOVERY`, `CONTENT_DISCOVERY`,
  `PARAMETER_DISCOVERY`, `VULNERABILITY_DETECTION`, `VULNERABILITY_VALIDATION`,
  `POC_SUPPORT`, `CALLBACK_VERIFICATION`, `GRAPHQL_ANALYSIS`,
  `SECRET_DISCOVERY`, `STATIC_ANALYSIS`, `PROXYING`, `EXPLOITATION`,
  `EXPLOIT_INTELLIGENCE`, `PAYLOAD_GENERATION`, `WORDLIST_PROVIDER`, …

Because different layers historically used different vocabularies (the TIP
taxonomy says `subdomain-discovery` while the arsenal said
`subdomain-enumeration`), Sprint 031 introduces
`CapabilityVocabulary` (`hunterx.tools.intelligence.vocabulary`) — a canonical
alias map. Selection, recommendation and chaining now canonicalize capability
ids so the whole toolchain speaks **one** capability language.

---

## 4. Tool Knowledge Contracts

Every integrated tool has a structured knowledge contract, synthesized by
`ToolKnowledgeFixtureRegistry` (`hunterx.tools.mastery.knowledge_fixtures`)
from the authoritative arsenal profiles. A fixture covers:

- identity / description / category / capabilities
- inputs (targets, protocols, required/optional)
- outputs (formats, structured formats)
- supported formats
- authentication and network requirements
- OS requirements and dependencies
- version information (known, constraints, parser/normalizer/adapter ids)
- scope considerations (scope requirements, safety class, destructive)
- resource requirements and rate limits
- safe defaults and dangerous operations
- limitations and known failure modes (error/warning/partial indicators)
- exit codes
- parser and normalizer
- evidence mappings (per capability → evidence type + validation required)
- observation mappings (per capability → canonical observation kind)
- follow-up actions (successors, validators, next tools)
- examples, operational knowledge, false-positive/negative risks

The three knowledge sources — **PayloadsAllTheThings**, **SecLists** and
**FuzzDB** — are integrated as versioned, licensed knowledge contracts
(`capability: payload-intelligence / wordlist-provider / attack-patterns`).
They are **knowledge inputs to hypotheses, testing, PoC generation and
validation — never blindly executed.**

---

## 5. Tool Selection

`ToolSelectionEngine` + `ToolSelector` rank candidate tools against criteria
(mission profile, target type, required capabilities, installed state, time,
compatibility, reliability, performance, preferences, safety ceiling). Every
selection produces an explanation:

- selected tool, capability, reason
- input source, expected output
- why alternatives were not selected
- risk and resource cost

`ToolRecommendationEngine` produces best / alternative / fallback /
complementary recommendations. `ToolchainService.strategies(capability)`
returns the canonical strategy: primary tool, ordered fallbacks,
complementary tools and the merge policy (deduplicate / correlate /
cross-validate / keep-separate).

### Fallbacks

Every major capability has fallback tools, e.g.:

- Subdomain: `subfinder` → `amass` → `assetfinder` → `findomain`
- Port scan: `naabu` → `rustscan` → `nmap` → `masscan`
- URL discovery: `katana` → `gospider` → `hakrawler` → `gau` → `waybackurls`

### Complementarity

Different tools produce different evidence. HunterX knows when outputs should
be merged, correlated, cross-validated, deduplicated or kept separate —
`Subfinder + Amass` never become duplicate subdomains (`EvidenceCorrelator`
deduplicates by canonical key).

---

## 6. Tool Chain Planning

`ToolSequencePlanner` builds dependency-aware chains in topological order, e.g.:

```
Subfinder → DNSx → HTTPx → Katana → Parameter Discovery → Nuclei → Validator
Nmap → service detection → technology identification → vulnerability testing
JS discovery → LinkFinder → extracted endpoints → HTTPx → parameter discovery → validation
```

Chains are dynamic; steps declare routing conditions (`ON_SUCCESS`,
`ON_FAILURE`, `ON_FINDING`, …) and per-step safety classes.

---

## 7. Structured Execution & Scope

Commands are built from structured configuration — **never** by concatenating
untrusted target input into a shell string. The SDK (`hunterx.tools.sdk`)
provides:

- `ExecutionContextBuilder` — typed arguments, validated paths
- `ExecutionSandbox` — permission enforcement, per-execution temp/output dirs,
  secret-safe environments, secret masking
- `ResourceManager` — CPU/memory/disk/network/thread/timeout budgets
- `ToolQueue`, `ParallelExecutionManager`, `RetryManager`, `TimeoutManager`,
  `ToolLockManager`, `ExecutionCache`
- `ExecutionPipeline` — register → install → validate → verify → prepare →
  execute → monitor → collect → validate → normalize → store → events → cleanup

Scope enforcement runs **before** every execution (`ToolEnforcementEngine`):
the target must be authorized and in scope; domain suffix containment is
supported (`api.example.com` is inside `example.com`); out-of-scope assets are
recorded but never attacked; redirects never auto-widen scope.

`ToolchainService` is the shared application facade (`hunterx.application.
toolchain`) that the CLI and API call for catalog, knowledge, health,
versions, requirements, provenance, recommendations, chains, guarded execution
and offline parse/normalize.

---

## 8. Parsers, Normalizers & Output Intelligence

HunterX prefers structured tool output (JSON, JSONL, XML, CSV, SARIF, NDJSON,
tool-native formats) and only falls back to textual parsing where necessary.
Every parser/normalizer is versioned; malformed input is skipped defensively;
empty output is an empty result (never an error); tool errors are classified
by `ToolOutputSemantics`.

`ToolchainService.parse(tool, raw)` and `.normalize(tool, records)` support
**offline replay** of saved tool output — essential for parser testing,
regression testing, golden datasets and reprocessing with new normalizers.

---

## 9. Evidence, Correlation & Confidence

From tool results HunterX extracts direct, supporting, candidate, negative,
execution, validation and metadata evidence. `EvidenceCorrelator`:

- deduplicates observations sharing a canonical identity (keeps highest
  confidence),
- groups them into `CorrelatedEvidenceChain`s (strongest evidence strength,
  ceiling-respected aggregate confidence),
- preserves **contradictions** (`ConflictingToolEvidence`) — tool A open vs
  tool B closed is never silently resolved; both are retained for validation.

`ToolEvidenceConfidence` evaluates tool reliability, result completeness,
output quality, version, validation state, corroboration and false-positive
characteristics. Tool output is **candidate evidence** (or validated
evidence) — never an automatic confirmed finding.

---

## 10. Security

Sprint 031 tests the toolchain attack surface:

- command injection through target → rejected shell metacharacters
  (`;&|\`$<>`)
- argument injection → typed structured values, never concatenated strings
- path traversal → sandboxed per-execution directories
- malicious tool output → treated as data, never executed
- malformed JSON/XML → defensively skipped
- oversized output → resource gate enforcement
- secret leakage → gitleaks redaction + sandbox masking invariants
- cross-target contamination → per-execution isolation
- scope bypass → scope gate before execution
- unsafe redirects → declared scope profile, never auto-widen
- resource exhaustion → rate-limit and resource gates

See `tests/security/test_toolchain_security.py`.

---

## 11. Resource Controls & Rate Limiting

`ToolRateLimitProfile` supports requests/sec, concurrency, burst, cooldown and
per-target limits. Effective limits are the **minimum** of all applicable
limits (tool, scope policy, mission policy, target policy, safety policy).
`ToolResourceRequirements` integrates with the SDK `ResourceManager` for CPU,
memory, disk, network, process count, timeout, concurrency, rate and request
budgets.

---

## 12. Versioning, Health & Installation

- `VersionManager` tracks installed versions and constraint satisfaction.
- `HealthChecker` verifies installed + version requirement + probe verdict.
- `ToolLifecycleManager` / `ToolStateMachine` manage
  `registered → installed → verified → available → running → completed | failed`.
- `ToolHealthMonitor`, `ToolPerformanceAnalyzer`, `ToolReliabilityTracker`
  feed selection and availability.
- Parser/normalizer contracts are versioned (`ToolParser`, `ToolNormalizer`).

---

## 13. Events

The toolchain publishes typed events (see `hunterx.domain.events`):

- `tool.execution.started` / `completed` / `failed`
- `tool.output.received` / `parsed` / `normalized`
- `tool.evidence.extracted`
- `tool.observation.created`
- `tool.result.contradiction`
- `tool.health.failed`
- `tool.version.detected`
- `tool.recommendation.created`

---

## 14. Interfaces

### CLI (`hunterx tools`)

```
hunterx tools list
hunterx tools show <tool>
hunterx tools capabilities [<tool>]
hunterx tools health [<tool>]
hunterx tools versions [<tool>]
hunterx tools execute <tool> <target> [--parameters JSON] [--mission <id>]
hunterx tools inspect-result <execution_id>
hunterx tools parse <tool> --raw <output|@file>
hunterx tools normalize <tool> --records <json>
hunterx tools chain <objective> --capabilities a,b,c
hunterx tools recommend <capability>
```

### API (`/tools`)

`GET /tools`, `GET /tools/{tool_id}`, `GET /tools/{tool_id}/capabilities`,
`GET /tools/{tool_id}/health`, `GET /tools/{tool_id}/versions`,
`GET /tools/{tool_id}/requirements`, `GET /tools/{tool_id}/provenance`,
`GET /tools/capabilities`, `GET /tools/recommend/{capability_id}`,
`POST /tools/chain`, `POST /tools/execute`,
`GET /tools/executions/{execution_id}/status|output|result`,
`POST /tools/parse`, `POST /tools/normalize`.

---

## 15. Testing

- **Unit** — `test_toolchain_service.py`, `test_toolchain_events.py`,
  `test_tool_knowledge_fixtures.py`, `test_tool_capability_vocabulary.py`,
  `test_toolchain_cli.py`
- **Component** — `test_toolchain_api.py`
- **Golden** — `test_toolchain_golden.py` (successful/empty/partial/error/
  malformed variants per tool category)
- **Acceptance** — `test_full_toolchain_acceptance.py` (cross-tool correlation,
  contradiction preservation, selection, chain planning, target intelligence)
- **Security** — `test_toolchain_security.py`
- **Performance** — `test_toolchain_performance.py` (parser/normalizer
  throughput, selection throughput)
- **Architecture** — `test_tool_layering.py` (tool modules never import higher
  layers; reporting never executes tools)
- **Engineering** — `test_regenerate_toolchain_manifest.py`

---

## 16. Extension Model

New tools are integrated through the Tool Integration SDK (`ToolAdapter`) and
registered with knowledge contracts in the arsenal specs
(`hunterx.tools.mastery.arsenal_*`). The canonical capability vocabulary must
be extended in `CAPABILITY_ALIASES` when a new tool introduces a new
capability id. Knowledge fixtures are synthesized automatically; golden
outputs and cross-tool correlation tests are added per tool category.

See `capabilities/full-toolchain-intelligence.json` for the ratified manifest
of every integrated tool and its capabilities.
