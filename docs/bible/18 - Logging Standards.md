# 18 — Logging Standards

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** All components; JSON logging; metrics; tracing; telemetry; audit

---

## 1. Logging Model

HunterX logs are **structured, correlatable, and machine-parseable**. The
default transport is JSON-lines to stdout plus optional file sinks. Human
readability comes from renderers, not from log prose.

Three correlated signals share the `trace_id`/`correlation_id`:

1. **Logs** (events)
2. **Metrics** (aggregate counters/histograms/gauges)
3. **Traces** (span trees)

---

## 2. Log Line Contract

Every log line is a JSON object with a canonical base schema:

```json
{
  "ts": "2026-08-05T12:34:56.789Z",
  "level": "info",
  "logger": "hunterx.engines.workflow",
  "correlation_id": "01J...",
  "span_id": "abc123",
  "trace_id": "def456",
  "actor": "operator@example.com",
  "module": "workflow",
  "message": "workflow.step_completed",
  "context": {"step_id": "port-scan", "duration_ms": 1234},
  "event_type": "workflow.step_completed",
  "schema_version": "1.0"
}
```

Rules:

- `ts` UTC ISO-8601 with `Z` and milliseconds.
- `level` in `debug|info|warning|error|critical`.
- `message` is a short, stable, event-style token (dotted) — **not** prose.
  Prose lives in `context` or in a dedicated renderer.
- `context` is a flat key/value map; nested structures discouraged (flatten or
  reference an object id).
- `correlation_id` propagates across a whole operation (mission, request, job).
- No secrets, tokens, cookies, credentials, or raw request bodies. Mask via
  `shared/masking`; verified by security tests.

---

## 3. Event Categories

| Category | Prefix | Examples |
|----------|--------|----------|
| System | `system.*` | `system.startup`, `system.shutdown` |
| Mission | `mission.*` | `mission.started`, `mission.phase_changed` |
| Workflow | `workflow.*` | `workflow.step_completed`, `workflow.resumed` |
| Task | `task.*` | `task.queued`, `task.retrying` |
| Tool | `tool.*` | `tool.completed`, `tool.failed`, `tool.rate_limited` |
| Finding | `finding.*` | `finding.created`, `finding.deduped` |
| Plan | `plan.*` | `plan.generated`, `plan.replanned` |
| AI | `ai.*` | `ai.call_started`, `ai.output_rejected` |
| Plugin | `plugin.*` | `plugin.loaded`, `plugin.ban` |
| Auth | `auth.*` | `auth.login_success`, `auth.login_failed` |
| Audit | `audit.*` | `audit.action` (append-only) |
| Degradation | `degradation.*` | `degradation.activated` |

---

## 4. Metrics Contract

- Exported via OpenTelemetry; Prometheus-compatible (`/metrics`).
- Naming: `hx_<component>_<name>_<unit>`.
- Mandatory base metrics for every subsystem:

| Metric | Type | Where |
|--------|------|-------|
| `hx_workflow_steps_total{status}` | counter | engine |
| `hx_workflow_step_duration_seconds` | histogram | engine |
| `hx_tool_runs_total{tool,outcome}` | counter | executor |
| `hx_tool_duration_seconds` | histogram | executor |
| `hx_ai_calls_total{capability,outcome}` | counter | AI engine |
| `hx_ai_latency_seconds` | histogram | AI engine |
| `hx_findings_created_total{category}` | counter | store |
| `hx_ingest_events_total` | counter | normalizer |
| `hx_queue_depth` | gauge | queue |
| `hx_worker_pool_utilization` | gauge | workers |
| `hx_db_query_duration_seconds` | histogram | store |
| `hx_cache_hit_ratio` | gauge | cache |
| `hx_degradation_activations_total` | counter | cross-cutting |
| `hx_http_requests_total{route,status}` | counter | API |
| `hx_http_request_duration_seconds` | histogram | API |

- Metrics cardinality bounded (tags enumerated); no per-target-cardinality
  explosion (e.g., no tag per URL).

---

## 5. Tracing

- OpenTelemetry spans per: API request, mission, workflow run, step, tool run,
  AI call, DB write.
- Span attributes: minimal and indexed (`step_id`, `tool`, `outcome`); full
  context in logs to avoid high-cardinality span tags.
- Distributed propagation: `traceparent`/`baggage` across workers and queues.
- Sampling: full sampling for missions/workflows; configurable rate for
  hot request paths; errors always sampled.
- Exporters: OTLP (default), Jaeger/OTel collector, or console in dev.

---

## 6. Audit Logging

- Separate append-only `audit` stream (event type `audit.*`) with **stronger
  guarantees** than operational logs.
- Mandatory audit events: authentication, authorization decisions, approval
  grants, scope policy changes, secret access, data export, plugin lifecycle,
  destructive tool execution, user/admin changes.
- Tamper-evidence: hash-chained or WORM-backed in enterprise mode
  (`13` §10).
- Never filtered or trimmed by standard log rotation; retention per policy
  (`09` §8).

---

## 7. Performance Logging

- Slow-query log (> 500ms) with query plan reference.
- Long-step log (steps exceeding profile budget).
- AI latency/cost per call logged (`ai.*`).
- Resource pressure warnings (memory, queue depth) at warning level.

---

## 8. Sensitive Data Handling

- **Masking module** applied at every boundary before emission.
- Masking patterns: secrets, tokens, cookies, basic-auth, password fields,
  AWS/cloud credentials, card/PII shapes.
- `redact` field marks lines that contain masked content.
- Security tests assert no secrets in logs (`15` §6).

---

## 9. Leveling & Volume Control

- `debug`: request-level detail, parser internals (opt-in).
- `info`: state transitions and completions only (default).
- `warning`: degradation, retries, cache misses at scale, throttling.
- `error`: recoverable failures with code.
- `critical`: service-level failure (worker down, DB unreachable, secret rotation failure).

- Rate limiting for log volume: per-event-type flood control; drop-and-count
  beyond threshold (log the drop).
- Logs in air-gapped mode: local sinks only; exporters optional.

---

## 10. Configuration

```yaml
logging:
  level: info
  format: json            # json|text(dev)
  sinks:
    - stdout
    - file: /var/log/hunterx/hunterx.log (rotation: 50MB x 10)
  tracing:
    enabled: true
    exporter: otlp
    sample_rate: 1.0
  metrics:
    exporter: prometheus
  audit:
    sink: append-only-file|postgres|worm
```

---

## 11. References

- `04 - Coding Standards.md` §4 (structured logging in code)
- `13 - Security Standards.md` §10 (audit)
- `17 - Error Handling Standards.md` (error events)
- `14 - Performance Standards.md` (perf metrics)
