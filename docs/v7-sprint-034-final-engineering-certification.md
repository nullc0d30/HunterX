# HunterX v7 — Sprint 034.6 — Final Engineering Certification

**Phase:** Final engineering certification before Sprint 035
**Status:** **BLOCKED** — 2× P0 and 5× P1 release blockers remain
**Date:** 2026-08-11
**Platform verified:** Windows 11 / Python 3.14.6 (installed `hunterx` 7.0.0, editable install of the v7 `src/` layout)
**Scope:** The complete integrated v7 platform (`src/hunterx`), mission lifecycle, toolchain, intelligence pipeline, persistence, evidence, PoC engine, recovery, observability, API/CLI, packaging, CI/CD and documentation.

This is the final engineering certification that Sprint 034.5 explicitly deferred
to. It audits the **complete** system as one integrated platform and re-checks the
release gates declared PASS in earlier 034.x reports. **Known defects are not
hidden**: this report surfaces unresolved blockers that earlier reports carried
as open or declared resolved prematurely.

---

## 1. System Certification

The SYSTEM FLOW

```
TARGET → SCOPE → RECON → ENUMERATION → DISCOVERY → INTELLIGENCE → PLANNING
→ TOOL SELECTION → EXECUTION → PARSING → NORMALIZATION → CORRELATION
→ HYPOTHESIS → TESTING → VERIFICATION → PROOF → PoC → REPLAY → IMPACT
→ FINDING → PERSISTENCE → REPORT
```

is implemented across the v7 stack and was verified end-to-end:

| Stage | Implementation | Verified |
|---|---|---|
| TARGET / SCOPE | `TargetIntelligenceEngine` (ingest_target), `MissionScopeGuard`, `scope_mission` | ✔ (tests) |
| RECON → DISCOVERY | `ReconService`, `DnsService`, `LiveHostService`, `CrawlService`, `JavaScriptService` | ✔ (tests) |
| INTELLIGENCE | `TargetIntelligenceEngine.run_cycle` (gaps → hypotheses → rank → actions) | ✔ 381 AI/intel tests |
| PLANNING / TOOL SELECTION | `DeterministicMissionPlanner`, `ToolSelector`, `ToolSequencePlanner`, `MissionToolSelector` | ✔ |
| EXECUTION | `ExecutionEngine` / SDK pipeline (`prepare→run→validate→normalize→cleanup`), `BinaryRunner` guarded seam | ✔ |
| PARSING / NORMALIZATION | `ParserEngine`, `ToolParser`, `ToolNormalizer`, `NormalizerEngine` → `CanonicalObservation` | ✔ 80 tools tests |
| CORRELATION | `TargetCorrelator` | ✔ |
| HYPOTHESIS / TESTING / VERIFICATION | `HypothesisLoopEngine`, `VulnerabilityValidationService` (verdict ladder) | ✔ |
| PROOF / PoC / REPLAY | `VulnerabilityProofService`, `PoCGenerator`/`PoCReplayVerifier`, `ProofValidator` | ✔ |
| IMPACT / FINDING | `ImpactAnalysisEngine`, `VulnerabilityFindingService`, `FindingLifecycleStateMachine` | ✔ |
| PERSISTENCE | TIDB stores (`SqlTidbRepositoryFactory`) + Alembic migrations | ✔ (see §8) |
| REPORT | `ProfessionalReportingService` (analyze→generate→QA→export, 6 formats) | ✔ live E2E |

No major subsystem is an isolated island: mission orchestration consumes
observations, findings and evidence from the toolchain/intelligence/proof
subsystems, and the reporting subsystem consumes persisted finding records.
One integration seam was found at report time (mission-context findings are not
auto-registered into the reporting finding store) — the intended flow requires
creating the finding via `VulnerabilityFindingService` (verified working).

**Verdict: the architecture is integrated and the pipeline works.**

---

## 2. End-to-End Results

Representative missions verified (deterministic, no real tool binaries required —
the certified design treats tool output as data; adapters are fixture-validated
and `tools`-marked tests are excluded by default, consistent with 034.5 §1):

| Mission type | How verified | Result |
|---|---|---|
| Web target | `hunterx hunt web_application_assessment https://example.com` (CLI, clean venv) | ✔ created + started |
| Web (deep) | `tests/acceptance/full_assessment` full-spectrum scenarios | ✔ 69 tests in batch |
| API target | acceptance API chain (api-graphql → inql/graphqlmap → nuclei) | ✔ 034.5 chain certified, tests pass |
| Cloud / SaaS | prowler / cloud-analysis chain scenarios | ✔ 034.5 chain certified |
| Repository / code | gitleaks → trufflehog → semgrep chain | ✔ 034.5 chain certified |
| Multi-stage | `tests/acceptance/test_autonomous_mission_acceptance.py` (SyntheticTargetEnvironment: recon→enum→vuln→validate→prove→report, injected failures) | ✔ |
| Integrated live flow | Custom harness on `build_platform()`: create → start → ingest (httpx/nuclei) → hypothesis → verify → finding → impact → finalize → finding persist (TIDB) → PoC → report generate → export | ✔ all steps true |

Live integration run (this certification, SQLite temp DB):
```
create ✓  start ✓  ingest ✓  hypothesis ✓  verify ✓  finding ✓  impact ✓
finalize ✓  finding_persisted ✓  poc_generated ✓  report_generate ✓
report_export ✓  observation_records ✓ (2 persisted)
```

**Mission state, persistence, events, evidence and reporting all function in
the integrated flow.**

---

## 3. Failure / Recovery

Failure-injection and recovery verification (all suites pass):

| Failure injected | Verification | Recovery verified |
|---|---|---|
| Tool missing binary / crash / timeout / non-zero exit / malformed / empty / rate-limit / network | `tests/tools/test_failure_handling.py`, `tests/security/tools/` | retry policy, capability-equivalent fallback (never blind), partial-result preservation |
| Chain step failure | `tests/acceptance/toolchain/test_chain_failure_falls_back_to_equivalent_tool` | fallback once to equivalent tool, `PARTIAL` chain result |
| Database dead URL | `tests/integration/tidb/test_persistence_failure_recovery.py` | `OperationalError` classified; healthy repo still works |
| DB constraint violation | same suite | `IntegrityError` rolled back, no duplicates |
| Mid-batch failure | `tests/integration/tidb/test_transaction_integrity.py` | `save_many` atomic, zero partial rows |
| Mission crash / resume | `MissionOrchestrator.checkpoint/resume_from_checkpoint`, `OffensiveOrchestrationEngine.run_mission(checkpoint_after_steps=N)`; integration + acceptance tests | checkpoint snapshots + `RESUMED` run linked to `resumed_from_run_id`/`checkpoint_id` |
| Event delivery | `InMemoryEventStore` replay, `InMemoryDeadLetterQueue` | store.replay + dead-lettering |
| Parser hostile input | `test_failure_handling.py::TestMalformedAndEmptyOutput` | malformed lines skipped, never executed |

**Known limitation (documented, not hidden):** DB retry/pool-pre-ping/failover
does not exist at runtime (`create_engine_from_settings` has no retry hook) and
in-memory fallback is config-time only — a deployment responsibility
(carried P3 from 034.3 §18).

---

## 4. AI Certification

- **No silent AI→evidence path exists.** `NullAIClient.complete()` raises
  `OperationError`; `embed()` is deterministic SHA-256 (verified live). The only
  real-provider consumer is the executive summarizer (a string, not evidence).
- **All reasoning is deterministic rule-based** in the certified path
  (OBSERVE→HYPOTHESIZE→PROBE→VERIFY); AI proposals are advisory
  (`ai_proposed` flag) and pass the same policy gates.
- **Validation gates verified:** `requires_validation=True` on all scanner
  adapters; candidate confidence capped at 0.5; `VerdictEngine`
  (CONFIRMED/FALSE_POSITIVE/INCONCLUSIVE); `ProofValidator` strict gate order
  (contradiction never averaged, target-state change ⇒ INCONCLUSIVE);
  `PoCReplayVerifier` (an HTTP 200 alone is never a successful replay);
  `ClaimVerifier` blocks unverified high-impact report claims.
- **Provenance:** hypotheses, decisions, observations, evidence and findings
  carry source/tool/version/correlation/mission refs; AI-inferred sources are
  ranked lowest (`AI_INFERENCE` weight 0.1).
- **Novel behavior:** `UnknownBehaviorClassifier` (KNOWN_CLASS / KNOWN_VARIANT /
  NOVEL_BEHAVIOR / APPLICATION_SPECIFIC / UNRESOLVED) — never labels zero-day
  without reproducible, security-relevant, controlled proof.
- **Tests:** 381 AI/validation/proof/reasoning tests pass (including golden +
  security matrices).

**Verdict: AI certification PASSES.**

---

## 5. Toolchain Certification

Carried forward from 034.5 (re-verified this sprint):

- **106 registered tools / 79 execution adapters**, complete machine-readable
  contracts (0 missing dimensions, `tests/tools/test_contracts.py`).
- All subprocess adapters run through the single guarded `BinaryRunner` seam
  (structural argv, no `shell=True`, 32 MiB cap, wall-clock timeout, injection
  guards).
- Parsers/normalizers fixture-validated for every family; golden fixtures under
  `tests/golden/tools/<family>/`.
- `ChainExecutor` (topological order, provenance, fallback, partial results)
  certified end-to-end for recon/API/secrets/web/cloud chains.
- `tests/tools` suite: **80 passed** when run explicitly.

---

## 6. Persistence Certification

- **Migrations:** 21 linear Alembic revisions, baseline `4302b30cb7c7`; verified
  `upgrade head` → 408 tables (file-backed SQLite), `alembic check` drift-free,
  downgrade clean (`tests/integration/tidb/test_sql_migrations.py`).
- **TIDB stores:** 401 `tidb_*` tables across missions, targets, findings,
  evidence, proof, PoC, reports, events, audit.
- **Transactions:** per-repository-call commits; `save_many` atomic
  (all-or-nothing). Verified by `test_transaction_integrity.py`.
- **Events/audit:** `InMemoryEventStore` replay + dead-letter; `VersioningListener`
  writes audit/timeline rows in SQL mode.
- **Findings/evidence/PoC/reports persist** across the service layer (verified
  live: `finding_persisted`, `observation_records`).

**Two persistence defects are NOT hidden:**
1. **Operational mission state is not resumable across process restarts** — the
   `MissionOrchestrator._missions` dict is in-memory only and `start()` has no
   restore path; TIDB persistence records audit/read-model data but cannot
   resume the orchestrator. See P1-03.
2. Timeline read-model (`tidb_mission_timelines`) is never written by the
   mission service (`GET /missions/{id}/timeline` returns empty in persistent
   deployments). Verified live. See P2-08.

---

## 7. Security Certification

- **Security test suites pass:** `tests/security` 396, `tests/security/tools`,
  `tests/security/api` (401/403/readonly auth matrix), `tests/security/test_proof_strategy_security`.
- **pip-audit:** no known vulnerabilities in `requirements.lock`.
- **Auth:** opt-in `X-API-Key` middleware verified (disabled by default on
  loopback — documented deployment guidance).
- **Secret handling:** masking regression pinned (`mask_value` `reveal_tail=0`
  bug fixed in 034.5); secret non-persistence tests pass.
- **BLOCKER — bandit gate fails:** 2× MEDIUM **B314** — untrusted XML parsed with
  stdlib `xml.etree.ElementTree.fromstring`:
  - `src/hunterx/domain/api/parsers/soap.py:73` — attacker-controlled WSDL
  - `src/hunterx/tools/livehost/nmap.py:138` — scanner XML output
  These are XXE / entity-expansion (billion-laughs) exposures for a tool that
  parses target-controlled XML. Fix: `defusedxml` (or hardened parser config).
  See P1-02. (46 LOW findings also present.)

---

## 8. Performance

Measured from the benchmark suite (`tests/performance`, 122 tests) and a
live N+1-query audit:

- **Throughput:** typical cores are µs-scale — e.g. `test_impact_benchmark`
  ~0.12 ms/op, correlation ~24 µs/op at 10k observations, selection throughput
  >100k ops/s, DNS resolution >2.5M ops/s, confidence >8M ops/s. No CPU
  bottleneck detected in the pure-domain hot paths.
- **Large sets:** `test_100k_observations_bounded` (~4.1s), 1M observation
  metadata diff (~1.7s), bulk insert 10k rows (21s setup) — bounded, no memory
  blow-up.
- **N+1 audit:** TIDB `list/list_by/get/count/stream` are single-query
  (cursor-counted, `tests/performance/persistence/test_n_plus_one.py`).
- **Known debt (P2, documented):** legacy `Sql*Repository.list()` is classic
  1+N; `save_many` issues a per-row existence SELECT; mission service loops
  `save()` per record; `MissionOrchestrationQueryService._records` lists up to
  10 000 rows then filters in Python.
- **BLOCKER — performance gate fails by design:** the gate runs the benchmark
  suite then flags any test >20s as "slow", so it flags its own benchmark
  functions (`test_hypothesis_creation_benchmark` 60.6s, `test_proof_creation_benchmark`
  37.3s) plus the 21s bulk-insert setup. The gate can never pass as configured.
  See P1/P2-01.

**Verdict: performance is acceptable in practice; the performance gate is broken.**

---

## 9. Observability

- **Structured logging:** `infrastructure/logging` `JsonFormatter` + `LoggingManager`.
- **Correlation IDs / mission IDs / execution IDs:** pervasive across TIDB
  models (`correlation_id`, `mission_id`, `execution_id` indexed columns), the
  event store, and log field binding.
- **Events:** typed event catalog (`domain/events/catalog.py`, ~100+ events),
  in-memory bus + append-only store + replay + dead-letter queue.
- **Metrics / telemetry:** `InMemoryMetrics`, `PrometheusTelemetryProvider`,
  `MemoryTelemetryProvider`, `InMemoryTracer`, health probes + health registry.
- **Audit trail:** `VersioningListener` (audit/change/version/timeline rows) in
  SQL mode.
- **Error tracing:** mission reasoning trace, decision records, tool execution
  records with failure kind + retry count.

**Verdict: observability is implemented and verified (tests in the default suite).**

---

## 10. API / CLI

- **API** (FastAPI, `create_app`): route groups `/missions`, `/missions/adaptive`,
  `/missions` dashboard, `/findings`, `/reports`, `/targets`+`/campaigns`,
  `/tools`, `/health`. Live verified in a clean `[api,db]` venv:
  `GET /health` → 200 `{"status":"ok"}`; `POST /missions` → 200 with `mission_id`.
- **API tests pass:** 43 integration/component/security API tests (incl.
  authorization matrix and mission lifecycle).
- **CLI** (`hunterx`, `hunterx-arch`): `version`, `--help`, `config`, `platform`,
  `mission`, `hunt`, `finding`, `report`, `target`, `campaign`, `tools`,
  `tools chain/chain-execute`, `hunterx-arch lint`. Verified in a clean venv.
- **Auth:** opt-in API-key middleware with admin/readonly roles; default off.
- **BLOCKER — CLI mission workflow cannot chain invocations** (`mission create`
  then `mission start <id>` fails with `AdaptiveMissionNotFoundError` because
  orchestrator state is in-memory). See P1-03. Also, `HUNTERX_*` env vars are
  never read. See P1-04.

---

## 11. Packaging / Clean Installation

- **`python -m eng packaging`: PASS** — wheel + sdist built, twine check clean
  (`dist/hunterx-7.0.0-py3-none-any.whl`, `hunterx-7.0.0.tar.gz`).
- **Clean-environment install test (fresh venvs, wheel):**
  - `pip install hunterx` (base, no extras): **CLI CRASHES** —
    `ModuleNotFoundError: No module named 'sqlalchemy'` at `hunterx.cli` import
    (through `infrastructure.db.sql.repositories`). **P0-02.**
  - `pip install "hunterx[api,db]"`: works — `hunterx version` → "HunterX v7.0.0",
    `hunterx-arch` 1.0.0, `tools list`, `mission create`, API server up.
- **Docker:** `Dockerfile` installs base `"."` (no extras) and healthchecks
  `hunterx version` → the image is **unhealthy at build** due to P0-02.
  `docker-compose.yml` is v6-era (build arg `VERSION: 6.0.0`, `HX_*` env, v6
  command surface) and inconsistent with the v7 Dockerfile (P2).
- **Entry points:** `hunterx = hunterx.cli:main`, `hunterx-arch = hunterx.architecture.cli:main`
  both resolve to the v7 `src/` package in a clean venv.

**Verdict: packaging gate passes, but the default install is broken (P0-02).**

---

## 12. CI/CD

18 workflows exist. Merge-gating: `ci.yml` (eng gates), `unit-tests`,
`integration-tests`, `performance-tests`, `security-tests`,
`packaging-validation`, `architecture-tests`, `docs-validation`, `compliance`,
`dependency-review`, `build`, `test`. Release/other: `release`, `sbom`,
`cosign-sign`, `docker-publish`, `pypi-publish`, `readiness`.

**CI cannot validate V7.** The `main` branch does not contain the v7 tree:
`git ls-files src` → 0 files; `eng/`, `tests/{unit,component,…}`, `alembic/`,
`capabilities/`, `config/` and the 14 new workflows are all untracked. A clean
checkout of `main` has only the v6 flat package (461 tracked files). Every CI
workflow that references `src`, `eng`, or the v7 test suites would fail or
error on a clean checkout. **P0-01.**

Mandatory gates as run against the **working tree** this sprint:

| Gate | Result | Detail |
|---|---|---|
| pytest | PASS | 3474 passed, 8 skipped, 2 deselected |
| mypy | PASS | clean |
| coverage | PASS | line-rate 81.7% (XML) ≥ 80%; combined 77% |
| architecture | PASS | exit 0 (warnings only) |
| docs | PASS | 7/7 |
| compliance | PASS | |
| hygiene | PASS | |
| dependencies | PASS | pip-audit clean |
| ruff | **FAIL** | 133 errors |
| deadcode | **FAIL** | vulture: 3 |
| security | **FAIL** | bandit B314 ×2 MEDIUM + 46 LOW |
| performance | **FAIL** | 3 tests > 20s (self-inflicted) |
| packaging | PASS | |

---

## 13. Documentation

- `docs` gate PASS (7/7: required files, required sections, engineering docs,
  internal links, fenced blocks, structure).
- Present: Development Bible (15 chapters), `docs/architecture/`, `docs/cli/`,
  `docs/configuration/`, `docs/installation/`, `docs/features/`, `docs/use-cases/`,
  `docs/v7-*.md` design/reference set (foundation, tidb, event-bus-observability,
  tool-integration-sdk, cicd-architecture, release-guide, security-pipeline,
  full-toolchain-intelligence, …), `CHANGELOG.md`, `ROADMAP.md`.
- **Incoherences (not hidden):** `docs/api.md`, `docs/cli.md`, `docs/AGENTS.md`
  document the **v6** API/CLI surface (`/agents`, `/scan`, agents/workflows)
  which does not exist in v7; root `hunterx.yaml` is v6 config; `RELEASE_CHECKLIST.md`
  and `install.sh` reference v6-era commands; the env-var configuration contract
  (loader docstring, `docs/configuration`) is **not implemented** (P1-04).
  No dedicated `deployment.md`/`migration.md` exists (deployment guidance lives
  in `docs/v7-release-guide.md` + docker posts).
- **Defect vs docs:** docs claim `HUNTERX_*` env overrides; the loader never
  reads them.

**Verdict: documentation is extensive and link-valid, but several critical
runtime behaviors depend on undocumented or unimplemented assumptions (env
config, base-install no-dependency mode).**

---

## 14. Test Matrix

| Suite | Collected | Result |
|---|---|---|
| unit | 2008 | PASS |
| component | 86 | PASS |
| integration | 283 | PASS (2 `tools`-deselected) |
| golden | 167 | PASS (7 skipped = intentional gate scenarios) |
| security | 396 | PASS |
| acceptance | 200 | PASS |
| performance | 122 | PASS (benchmarks run) |
| engineering | 91 | PASS |
| architecture | 129 | PASS |
| **tools** | **80** | **PASS when run explicitly — NOT in default testpaths (P2-03)** |
| **Full default suite** | **3484** | **3474 passed, 8 skipped, 2 deselected** |

Empty or misleading suites:
- `tests/framework/` contains helpers/fixtures only (correct, not a suite).
- `tests/tools/` (80 tests, the Sprint 034.5 toolchain certification suite) is
  **missing from `[tool.pytest.ini_options] testpaths`** — `python -m pytest` and
  the CI pytest gate do not run it. Sprint 034.5 reported these as part of the
  default run; that is inaccurate. Misleading.
- `tests/performance` benchmark functions are themselves flagged as "slow" by
  the performance gate — the gate's own output is misleading (P2-01).
- `tests/test_reasoning.py` at the repo root targets removed v6/v5
  `core.reasoning_engine_old` — it cannot collect against v7; excluded from
  testpaths (stale, harmless).

---

## 15. Known Issues

| # | Severity | Description | Evidence |
|---|---|---|---|
| K01 | P0 | Entire V7 tree untracked in git (`src/`, `eng/`, v7 `tests/`, `alembic/`, `capabilities/`, `config/`, 14 workflows, `requirements.lock`, v7 docs) — CI/release cannot validate V7 from a clean checkout | `git ls-files src` = 0; 103 untracked entries; carried from 034.1 P0-01, still open |
| K02 | P0 | Base install (no extras) crashes at import — sqlalchemy required by `infrastructure/db/sql/*` unconditionally; breaks `pip install hunterx`, the Docker image, and the documented zero-dependency mode | clean venv install test; Dockerfile `pip install "."` + `hunterx version` healthcheck |
| K03 | P1 | ruff gate red: 133 errors (UP007×39, D102×25, I001×21, UP035×14, F401×12, B023×7, …) — mandatory CI gate fails | `ruff check src eng tests alembic` |
| K04 | P1 | bandit B314 ×2 MEDIUM: XXE/entity-expansion via stdlib `ET.fromstring` on attacker-controlled WSDL (`soap.py:73`) and nmap XML (`nmap.py:138`) — security gate red | `bandit -r src/hunterx` |
| K05 | P1 | Mission orchestration state is in-memory only — no restore path; `mission start`/`checkpoint`/`resume` fail across process restarts even with SQL persistence; CLI `create`→`start` broken | live CLI + orchestrator `get()` audit (orchestrator.py:208-215) |
| K06 | P1 | `HUNTERX_*` env config never applied — loader ignores environment (docstring/settings/docs promise it); breaks config-by-env for containers/CI | `loader.py` has no env read; `HUNTERX_DATABASE_URL` ignored (verified) |
| K07 | P1 | deadcode gate red: vulture 3 (dead `if False else 0` in `telemetry.py:44`, unused `fp`/`msg` params in `httpclient.py:89`) | `vulture` run |
| K08 | P2 | Performance gate cannot pass as configured (flags its own benchmark tests >20s); throughput itself is fine | gate run + durations |
| K09 | P2 | Legacy SQL repo N+1, per-row existence SELECT in `save_many`, service-level table scans, per-entity commit loops | 034.3 §10/§18, verified |
| K10 | P2 | `tests/tools` (80) excluded from default testpaths — CI pytest gate misses the toolchain certification suite | pyproject testpaths |
| K11 | P2 | Timeline read-model never written (`tidb_mission_timelines`) — `/missions/{id}/timeline` empty in persistent deployments | live E2E (timeline_records=false) |
| K12 | P2 | Unguarded select-then-insert race on concurrent first-time upsert (IntegrityError) | 034.3 concurrency suite |
| K13 | P2 | `docker-compose.yml` v6-era; root `hunterx.yaml` v6 config; `docs/api.md`/`docs/cli.md`/`docs/AGENTS.md` document v6 API/CLI | audit |
| K14 | P2 | Coverage combined (branch-adjusted) is 77% — only the XML line-rate (81.7%) passes the 80% gate | coverage run |
| K15 | P2/P3 | ~30 arsenal tools knowledge-only; interactsh/metasploit/mitmproxy/zap execution-dependent; chain fan-out single-target; report redactor limits; PATH-resolved binaries w/o integrity pinning; no per-CPU rlimit | 034.5 §18/§19 carried |
| K16 | P3 | `RELEASE_CHECKLIST.md`, `install.sh`, `RELEASE_NOTES_v6.0.0.md` reference v6-era commands/versions | audit |

---

## 16. P0 / P1 / P2 / P3 Summary

### P0 — release blockers (2)
| # | Issue | Status |
|---|---|---|
| K01 | V7 tree untracked in git — CI/release cannot validate V7 | **Open (carried from 034.1, declared resolved in 034.2–034.5 — incorrect)** |
| K02 | Base install/Docker image crash (unconditional sqlalchemy import) | **Open (new)** |

### P1 — must fix (5)
| # | Issue | Status |
|---|---|---|
| K03 | ruff gate red (133) | **Open** (was P2-08 in 034.1, now worse; 034.5 "no P1" claim wrong) |
| K04 | bandit B314 XXE ×2 — security gate red | **Open (new)** |
| K05 | Mission orchestrator not resumable across restarts | **Open (new)** |
| K06 | Env config (`HUNTERX_*`) unimplemented | **Open (new)** |
| K07 | deadcode gate red | **Open (new)** |

### P2 — acceptable technical debt (8)
K08 performance-gate self-fail, K09 N+1/commit loops, K10 tools suite not in
testpaths, K11 timeline read-model unwritten, K12 concurrency upsert race,
K13 v6-era compose/config/docs, K14 combined coverage 77%, K15 carried toolchain
gaps (knowledge-only adapters, fan-out, redactor, binary pinning, rlimits).

### P3 — post-release (2)
K16 stale v6 checklists/installer references; plus carried items (no DB
runtime failover, CODEOWNERS gaps, `__main__.py` absence).

---

## 17. Release Readiness Score

Scoring model: 100 − 30×(#P0) − 15×(#P1) − 3×(#P2), floor 0.

- P0 = 2 → −60
- P1 = 5 → −75
- P2 = 8 → −24
- **Release Readiness: 0/100 (blocked)**
- Quality gates passing: 9/13 mandatory gates green on the working tree
  (pytest, mypy, coverage, architecture, docs, compliance, hygiene,
  dependencies, packaging) vs 4 red (ruff, deadcode, security, performance).
- Test suite health: **100% green** (3474 passed; +80 tools suite green when run).

The product code and tests are healthy and green; the **release engineering
envelope is not** (git state, default install, security/deadcode/ruff gates,
mission resumability, env config).

---

## 18. Final Gate

| Gate | Requirement | Result |
|---|---|---|
| [ ] | end-to-end missions work | ✔ PASS (live + acceptance) |
| [ ] | persistence works | ⚠ PARTIAL (records persist; orchestrator not resumable — P1) |
| [ ] | toolchain works | ✔ PASS (contracts/chaining/parsing; 80 tests green when run) |
| [ ] | intelligence pipeline works | ✔ PASS (381 tests) |
| [ ] | evidence works | ✔ PASS (evidence-gated lifecycle) |
| [ ] | PoC lifecycle works | ✔ PASS (generate→validate→replay→verdict) |
| [ ] | recovery works | ✔ PASS (tool/DB/mission-step/event injection suites) |
| [ ] | security gates pass | ✖ FAIL (bandit B314 ×2; ruff/deadcode also red) |
| [ ] | performance is acceptable | ⚠ PARTIAL (throughput fine; gate broken) |
| [ ] | API works | ✔ PASS (live /health, /missions; auth verified) |
| [ ] | CLI works | ✖ FAIL (cross-invocation mission workflow broken — P1) |
| [ ] | clean installation works | ✖ FAIL (base install crashes — P0-02) |
| [ ] | CI validates V7 | ✖ FAIL (V7 untracked — P0-01) |
| [ ] | documentation is coherent | ⚠ PARTIAL (link-valid; v6 API/CLI docs + unimplemented env config) |
| [ ] | no P0 remains | ✖ FAIL (2 P0) |
| [ ] | no unresolved P1 release blocker remains | ✖ FAIL (5 P1) |

---

## 19. Final Recommendation

**STOP. Do NOT begin Sprint 035.**

**Sprint 034.6 — FINAL ENGINEERING CERTIFICATION: BLOCKED.**

The engineering substance of HunterX v7 is strong and healthy — the integrated
platform works end-to-end, all 3474 default tests pass, the toolchain and
intelligence/proof pipelines are certified, and no functional regression was
found. But the **release is not ready** because the engineering gate envelope
fails:

1. **P0 — the v7 delivery is not in git.** A clean `main` checkout cannot build,
   test or release V7. This is Sprint 034.1's own P0-01, never closed; later
   034.x reports declared "no P0" inaccurately.
2. **P0 — the default install is broken.** `pip install hunterx` crashes at
   import without the optional `db` extra; the Docker image healthcheck fails.
3. **P1 — three mandatory CI gates are red** (ruff 133, bandit B314 XXE ×2,
   deadcode) and the performance gate can never pass as configured.
4. **P1 — two runtime contract breaks:** mission orchestration state is not
   resumable across process restarts, and `HUNTERX_*` environment configuration
   is documented but never implemented.

Exact remaining blockers (minimum to unblock):
- Commit the complete v7 tree (P0-01) and re-run CI on a clean checkout.
- Make `db/sql` imports lazy (or add `db` to core deps) so the base wheel and
  Docker image run (P0-02).
- Fix bandit B314 XXE with `defusedxml` (P1-04).
- Add a mission-restore path (hydrate `OrchestratedMission` from TIDB on
  `start`/`resume`) so CLI/API workflows survive restarts (P1-03).
- Implement env-var application in the config loader (P1-06).
- Clean the 133 ruff violations and 3 vulture findings (P1-03/P1-05), and fix
  the performance-gate slow-test logic (P2-01).

Sprint 035 may begin only after the P0 items are closed and the P1 items are
resolved or explicitly re-scoped with acceptance criteria.
