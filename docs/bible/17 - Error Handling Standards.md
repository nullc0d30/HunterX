# 17 — Error Handling Standards

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** All layers; exception taxonomy; retries; rollback; graceful degradation; recovery

---

## 1. Philosophy

HunterX treats failures as **first-class, observable, and recoverable events**.
Errors are never silent, never swallowed, and never leave the system in an
unknown state. The platform **fails loud but degrades gracefully**.

---

## 2. Exception Taxonomy

Root: `HunterXError`. Hierarchy:

```
HunterXError
├── ConfigurationError        (bad config/manifest/schema)
├── ScopeViolationError       (HX-SCOPE-*)        [non-retryable, critical]
├── ValidationError           (HX-VALID-*)        [non-retryable]
├── NotFoundError             (HX-NF-*)           [non-retryable]
├── AuthenticationError / AuthorizationError      [non-retryable]
├── TransientError            (HX-TRANS-*)        [retryable]
│   ├── NetworkError
│   ├── TimeoutError
│   ├── RateLimitedError
│   ├── ProviderUnavailableError
│   └── ToolCrashedError
├── PermanentError            (HX-PERM-*)         [non-retryable]
│   ├── ToolMissingError
│   ├── UnsupportedModeError
│   ├── ParseError
│   └── DataIntegrityError
└── CancelledError            (HX-CANCEL-*)       [no retry]
```

Rules:

- Every exception carries: `code` (stable machine string), `message`
  (safe, no secrets), `retryable` flag, `context` (dict), and is logged with
  `correlation_id`.
- Domain errors are defined in `domain/exceptions`; infra errors map to these.
- Never raise raw third-party exceptions across layer boundaries; translate at
  adapter boundaries.

---

## 3. Error Codes

Format: `HX-<AREA>-<NNN>`. Areas: `SCOPE`, `VALD`, `TRANS`, `PERM`, `AUTH`,
`CFG`, `PLUGIN`, `TOOL`, `DB`, `AI`, `QUEUE`, `CANCEL`.

Codes are registered in `docs/bible/README.md` error-code table (or linked
register) and are stable across releases (new codes added; never reused).

Example:

| Code | Meaning | Retryable |
|------|---------|-----------|
| HX-SCOPE-001 | Target outside engagement scope | no |
| HX-TRANS-001 | Transient network failure | yes |
| HX-TRANS-002 | Tool timed out | yes (bounded) |
| HX-PERM-001 | Tool binary missing | no |
| HX-AI-001 | AI output failed schema validation | yes (bounded) |
| HX-DB-001 | Store unavailable | yes (bounded) |
| HX-PLUGIN-001 | Plugin load failure | no |

---

## 4. Failure Handling by Layer

| Layer | Behavior |
|-------|----------|
| Domain | Raise typed domain errors; never I/O errors leak in |
| Application | Map use-case outcomes; do not leak stack traces to delivery |
| CLI | Print `code`, safe message, and remediation hint; exit code per table |
| API | JSON error envelope (`20` §Errors) |
| Worker/Engine | Step-level retry → degrade → pause → fail (per `10` §7) |
| Adapter | Translate tool failures to typed outcomes (`06` §13) |

---

## 5. Retry Policy

- Retries are **always bounded** (max attempts + backoff + jitter).
- Only `retryable=True` errors retry.
- Backoff: exponential by default (`base=1s`, `factor=2`, `max=60s`, jitter).
- Retry budgets: per-step (workflow), per-mission, per-AI-call.
- Retry counters and final outcome recorded in telemetry and audit.

| Policy | Default |
|--------|---------|
| Transient network | 3 attempts |
| Tool timeout | 2 attempts |
| Rate limited | up to policy, honor `Retry-After` |
| AI schema failure | 2 attempts then fallback |
| DB unavailable | 3 attempts then degrade |
| Scope violation | never retried; abort + alert |

---

## 6. Rollback

- **Transactional steps** (DB writes, evidence storage): full rollback on
  failure — nothing half-persisted; events are idempotent.
- **External side effects** (tool actions): cannot be universally rolled back.
  Document per tool in its knowledge file (`07` §Errors) the cleanup/rollback
  steps. Where possible, the executor runs cleanup hooks.
- **Compensating actions:** for multi-step operations with side effects,
  define compensating steps in the workflow (e.g., revoke a created account in
  a test environment).
- Partial successes are **preserved**, never discarded; the audit trail records
  exactly what succeeded.

---

## 7. Graceful Degradation

Degradation ladder (applied in order, recorded in events/logs):

1. **Fallback:** use alternate provider/tool/strategy (AI → rule-based;
   provider A → B; tool X → Y with same capability).
2. **Route around:** mark tool unavailable; continue with peers; skip with reason.
3. **Scope reduction:** execute reduced-profile (fast over thorough).
4. **Pause for operator:** stop and request intervention (approval gate).
5. **Fail the unit, preserve the mission:** isolate failed step; mission may
   complete-with-warnings.

Degradation is **observable**: `degradation.activated` event with reason and
level; metrics `hx_degradation_activations_total`.

---

## 8. Recovery & Resume

- Workflows: resume from checkpoint (`10` §6–7).
- Missions: on crash/restart, `MissionService` reconciles state from TIDB;
  in-flight runs resume or are marked for operator review.
- Queue: at-least-once delivery; consumers idempotent; DLQ captures poison
  messages for inspection.
- Databases: transactional integrity + WAL point-in-time recovery
  (`09` §11).

---

## 9. Operator-Facing Errors

- Errors in CLI/API are: actionable (what happened), safe (no internals,
  no secrets), and referencable (error code).
- Every error output includes a remediation hint or a docs link.
- Machine-readable: API returns `{error: {code, message, details?, retryable,
  correlation_id}}`; CLI `--output json` emits the same envelope.

---

## 10. Testing Error Paths

- Every retry policy has a unit test (attempt limits, backoff, jitter bounds).
- Failure injection: integration tests inject provider/tool/DB failures and
  assert degradation behavior (`15` §3).
- Chaos-style tests (nightly): random timeouts, killed workers, provider
  outages → assert no data loss, graceful degrade, resume works.

---

## 11. References

- `10 - Workflow Engine.md` §7 (workflow recovery) & §11 (error classes)
- `13 - Security Standards.md` §7 (tool execution safety)
- `18 - Logging Standards.md` (error event fields)
- `19 - CLI Standards.md` / `20 - REST API Standards.md` (surface errors)
