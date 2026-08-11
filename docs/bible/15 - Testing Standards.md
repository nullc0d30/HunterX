# 15 — Testing Standards

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** All code, `tests/`, CI gates, golden datasets

---

## 1. Testing Pyramid

```
          acceptance (E2E, few)
         integration (adapters, API, DB)
        unit (many, fast, isolated)
      component (per subsystem, in-process)
    ────────────────────────────────────
    golden (regression datasets, cross-layer)
```

| Level | Scope | Environment | Speed |
|-------|-------|-------------|-------|
| unit | functions/classes in isolation | in-memory, no I/O | < 50ms each |
| component | one subsystem with ports faked | in-process | < 1s |
| integration | real adapters (DB, queue, tool binaries) | dockerized/CI services | seconds |
| golden | parser→normalizer→store pipelines | fixtures | seconds |
| acceptance | full mission on sandboxed target | e2e compose | minutes |
| performance | benchmarks & load | dedicated | hours (nightly) |

---

## 2. Unit Tests

- One test module per production module (`test_<module>.py`).
- No network, no real DB, no subprocess, no AI provider (all via fakes).
- Domain tests use real objects with injected fakes; no mocks of domain internals.
- Property-based tests (`hypothesis`) for parsers, normalizers, canonicalizers.
- Table-driven where sensible.
- **Naming:** `test_<behavior>_<condition>`.

---

## 3. Integration Tests

- Real PostgreSQL/Redis/queue against test databases (CI services or docker-compose).
- Adapter tests run real tool binaries where available; otherwise skipped with
  marker `@pytest.mark.tools` (explicit skip rationale logged).
- API tests exercise routes against the real app factory with the same
  dependency overrides used in production composition.
- AI provider tests use a **mock provider** implementing the provider contract
  (no external calls); one smoke test per real provider gated by env key.

---

## 4. Regression Tests

- Every bug fix ships with a regression test that fails on the old behavior.
- Golden tests guard parser/normalizer output stability
  (`data/golden/`): inputs → expected canonical events; any schema/output change
  requires updating goldens deliberately (reviewed in PR).

---

## 5. Performance Tests

- `tests/performance/` benchmarks via `pytest-benchmark`.
- CI gate: hot-path benchmarks regress ≤ 10%.
- Nightly load tests: ingest 10k/s, 1M-finding triage, 1,000 concurrent targets.
- Failure = artifact (flame graph, profile) attached for triage.

---

## 6. Security Tests

- **Sandbox escape:** fixtures attempt escapes; assert blocked + quarantined.
- **Injection:** tool args with `;`, `|`, `$(...)`, path traversal, template
  injection — assert neutralization.
- **Secret leakage:** run representative paths; assert no secrets in logs,
  errors, reports, or AI prompts (grep-style assertions on masked output).
- **Scope enforcement:** out-of-scope target rejected at planner, executor, and
  sandbox.
- **RBAC:** forbidden resource access returns 403; tenant isolation verified.
- **Deserialization:** malicious payloads rejected.
- **Prompt injection:** poisoned tool output does not alter decisions
  (`UNSUPPORTED` flagged).
- **Supply chain:** dependency scan + plugin signature verification tests.
- See `13 - Security Standards.md` §15.

---

## 7. Golden Dataset

Located `data/golden/`. Structure:

```
data/golden/
├── tools/<tool-id>/
│   ├── input_<case>.txt|jsonl      # raw tool output fixture
│   └── expected_<case>.json         # expected canonical events
└── workflows/<workflow-id>/         # end-to-end pipeline goldens
```

Rules:

- Goldens are versioned; changes are deliberate and reviewed.
- Every parser change must update or add goldens.
- A golden mismatch fails CI unless the golden file itself is updated in the PR.

---

## 8. Acceptance Tests

- Full mission runs on **sandboxed/vulnerable-by-design targets**
  (e.g., DVWA, OWASP Juice Shop, Metasploitable in isolated docker network).
- Assert: mission completes, expected findings present with evidence, reports
  generated in required formats, no scope violation, audit log populated.
- Acceptance criteria per profile: see `24 - Quality Assurance.md` §2.

---

## 9. Coverage Requirements

| Area | Minimum coverage |
|------|------------------|
| `domain` | 95% |
| `application` | 85% |
| `engines` | 80% |
| `infrastructure` (non-boilerplate) | 70% |
| tools/adapters (per tool) | 80% of parser+normalizer+adapter |

- Coverage enforced in CI (`coverage` + threshold fail).
- Exceptions (adapters without binaries) require explicit `# pragma: no cover`
  with justification, reviewed.

---

## 10. Test Doubles

- **Fakes** for ports (in-memory stores, fake queue, fake cache) — preferred.
- **Stubs** for canned tool outputs.
- **Mock provider** for AI contract testing.
- **Spies** for event-bus assertions.
- Mocks used sparingly and only at boundaries; no mocking of the code under test's own modules.

---

## 11. CI Execution

| Stage | Command | Gate |
|-------|---------|------|
| Lint/format | `ruff check`, `ruff format --check` | must pass |
| Types | `mypy --strict` | must pass |
| Architecture | import-linter rules | must pass |
| Unit | `pytest tests/unit` | must pass, coverage gates |
| Golden | `pytest tests/golden` | must pass |
| Component | `pytest tests/component` | must pass |
| Integration | `pytest tests/integration` | must pass (services up) |
| Security | `pytest tests/security` | must pass |
| Performance smoke | benchmarks subset | regress ≤ 10% |
| Acceptance | nightly / release | must pass |
| Coverage | aggregate | meet thresholds |

---

## 12. Local Testing Commands

```bash
pytest                                   # default: unit+golden+component
pytest -m integration                    # integration (needs services)
pytest -m tools                          # real tool binaries
pytest -m security                       # security suite
pytest -m perf --benchmark-enable        # performance subset
```

---

## 13. References

- `04 - Coding Standards.md` §14 (code review gates)
- `13 - Security Standards.md` §15 (security tests)
- `14 - Performance Standards.md` §9 (performance tests)
- `22 - Tool Integration Standard.md` §Tests
