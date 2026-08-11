# 10 — Workflow Engine

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** `engines/workflow.py`, mission pipelines, plan execution, scheduling

---

## 1. Purpose

The Workflow Engine executes **Directed Acyclic Graphs (DAGs)** of steps. It is
the deterministic execution backbone of every mission. It handles dependencies,
parallelism, retries, validation, checkpoints, and recovery — while the Planner
(`02` §5.5) decides *what* the graph looks like and the Mission Engine decides
*why* the mission runs.

---

## 2. Concepts

| Concept | Definition |
|---------|------------|
| `WorkflowRun` | One execution of a workflow (or plan). Has id, status, correlation_id. |
| `Step` | A node in the DAG. Has id, type, input, output contract, retry policy. |
| `Edge` | `depends_on` relationship; forms a DAG (cycle detection enforced). |
| `Checkpoint` | A saved point in time at a step boundary enabling resume. |
| `Pipeline` | An ordered composition of phases; each phase is a workflow. |
| `Task` | The atomic execution unit the scheduler dispatches. |

---

## 3. Step Types

| Type | Behavior |
|------|----------|
| `agent` | Delegate to an agent (via AgentOrchestrator); agent may emit goals |
| `tool` | Execute a tool via ToolExecutor (adapter + sandbox) |
| `skill` | Execute a security skill from the Skill Registry |
| `condition` | Branch on a boolean expression over accumulated output |
| `parallel` | Run child steps concurrently (fan-out) with a join barrier |
| `loop` | Repeat child steps while a condition holds; bounded by max_iterations |
| `wait` | Pause for duration or until condition/event |
| `transform` | Pure data transform (aggregate, map, dedup) — no I/O |
| `submission` | Require operator approval/input (approval gate) |
| `notify` | Emit an event / external notification; non-blocking |
| `ai` | Invoke AI decision through the AI Engine (never direct) |
| `report` | Render a report view |

---

## 4. Workflow Definition (Contract)

Workflows are defined in YAML (mission profiles) or JSON (API). Contract:

```yaml
id: external-recon
version: 1
phases:
  - id: discovery
    steps:
      - id: subdomain-enum
        type: tool
        tool: subfinder
        mode: passive
        profile: fast
        input: { target: "<target>", scope: "<scope>" }
        output_schema: subdomain
        depends_on: []
      - id: dns-resolve
        type: tool
        tool: dnsx
        input: { targets: "ref:subdomain-enum" }
        depends_on: [subdomain-enum]
  - id: detection
    steps:
      - id: port-scan
        type: tool
        tool: nmap
        profile: stealth
        depends_on: [dns-resolve]
      - id: nuclei-scan
        type: tool
        tool: nuclei
        profile: fast
        depends_on: [port-scan]
        retry: { max_attempts: 2, backoff: "exponential", retryable: [transient, timeout] }
      - id: high-sev-gate
        type: condition
        condition: "output.findings.max_severity in ('high','critical')"
        true: [validation]
        false: [report]
        depends_on: [nuclei-scan]
      - id: validation
        type: tool
        tool: sqlmap-validate
        requires_approval: true        # destructive-class
        depends_on: [high-sev-gate]
```

Execution semantics:

- Steps run when all `depends_on` complete with success.
- A `parallel` step's children run concurrently; the join waits for all.
- `condition` evaluates over the accumulated **step output namespace**
  (`output.<step_id>.<field>`).
- `loop` requires `max_iterations` (default 3, hard cap enforced).

---

## 5. Execution Model

### 5.1 Scheduling & Concurrency

- Async task scheduler (`asyncio`) with a worker pool; per-mission and global
  concurrency limits enforced by the queue (`02` §5.18).
- Ready set = steps whose dependencies completed; dispatched in priority order
  (plan priority × profile priority).
- Fan-out bounded by `max_concurrency` in the step/profile.

### 5.2 Validation Gates

- Every step declares `output_schema`; output is validated before the step is
  marked complete.
- Validation failure → `step.failed` with reason; per retry policy.
- Findings from steps are validated against `08 - Unified Security Schema.md`.

### 5.3 Retries

Per-step policy:

```yaml
retry:
  max_attempts: 3
  backoff: exponential   # exponential|linear|fixed
  base_delay_s: 1
  max_delay_s: 60
  jitter: true
  retryable: [transient, timeout, rate_limited]   # outcome classes
```

- Non-retryable failures (scope violation, invalid config) fail immediately.
- Retry exhaustion → step failed → workflow recovery (below).

### 5.4 Cancellation

- Graceful: stop scheduling new steps; let in-flight finish; mark `cancelled`.
- Forceful: kill in-flight tasks (sandbox kills subprocesses), mark `cancelled-forceful`.
- Cancellation is operator- or policy-triggered (scope breach, window expiry).

---

## 6. Checkpoint System

- A checkpoint is taken **at every step boundary** (before dispatch) and
  periodically during long-running steps (configurable interval).
- Checkpoint payload: step outputs (content-addressed), step statuses, plan
  version, mission state, scope, correlation_id.
- Checkpoints are stored in TIDB (`workflow_runs`, `task_runs`) + object store
  for blobs; ids recorded on the run.
- **Resume:** a failed/crashed run can resume from the last checkpoint —
  completed steps are not re-run (idempotent consumers).
- **Determinism:** resume replays the same plan (plan_id unchanged) unless the
  operator chooses replan; replan creates a new plan version (logged).

---

## 7. Recovery

Failure handling hierarchy:

```
step failure
  → retry policy (bounded)
  → route around (mark tool unavailable; skip with reason)
  → degrade phase (execute fallback profile / reduced scope)
  → pause workflow for operator intervention (requires_approval)
  → fail workflow (mission recovery path)
```

Recovery rules:

- Tool unavailable → mark unavailable for the mission, continue with peers, log.
- AI provider down → degrade to rule-based fallback for planning/triage.
- Partial results are **preserved**; nothing already persisted is rolled back.
- Workflow-level rollback is only for **transactional data steps** (not for
  tool side effects); side-effect rollback is documented per tool in its
  knowledge file.

---

## 8. Mission Execution Integration

Mission Engine drives a **pipeline** = ordered phases. Each phase is a workflow.

```
mission.started
  ├─ phase: recon (workflow)
  │    └─ workflow.completed → mission.phase_completed
  ├─ phase: detection (workflow)
  ├─ phase: validation (workflow; approval gates)
  ├─ phase: correlation (workflow: transform steps)
  └─ phase: reporting (workflow: report steps)
mission.completed
```

- Phases may overlap only when declared non-blocking (e.g., continuous mode).
- Every phase transition is recorded in the mission timeline and event bus.

---

## 9. Determinism & Reproducibility

- Plan and workflow graphs are content-addressed:
  `graph_id = sha256(profile, scope, params, workflow_version)`.
- Tool invocations reuse cached idempotent outputs where the knowledge file
  declares cacheability.
- AI steps are recorded with seeds/params so replays are reproducible
  (subject to provider nondeterminism, which is recorded, not hidden).

---

## 10. Monitoring & Observability

Every step/run emits:

| Event | Fields |
|-------|--------|
| `workflow.started` | run_id, plan_id, graph_id |
| `workflow.step_started` | step_id, type, tool/agent |
| `workflow.step_completed` | step_id, duration_ms, output ref |
| `workflow.step_failed` | step_id, error, code, retryable |
| `workflow.step_retrying` | attempt, delay |
| `workflow.checkpoint_saved` | checkpoint_id, offset |
| `workflow.resumed` | from_checkpoint |
| `workflow.completed` / `workflow.failed` | summary, duration |

Traces: one span per run; child spans per step/task; per-step metrics
(`hx_workflow_step_duration_seconds`, `hx_workflow_step_failures_total`).

---

## 11. Error Classes (see also `17 - Error Handling Standards.md`)

| Class | Example | Retryable |
|-------|---------|-----------|
| `transient` | network blip, tool crash | yes |
| `timeout` | step exceeds deadline | yes (policy) |
| `rate_limited` | 429 from target/API | yes (backoff) |
| `invalid_input` | bad mode/params | no |
| `scope_violation` | target out of scope | no; abort + alert |
| `config_error` | bad workflow def | no |
| `approval_required` | gate reached | pause, wait |

---

## 12. Performance Budget

- Step dispatch overhead < 5ms.
- Long-running steps stream results; no unbounded buffering.
- Checkpoint save target < 500ms for a mid-size mission.
- Concurrency limits are configurable and enforced globally to protect the
  platform (see `14 - Performance Standards.md`).

---

## 13. References

- `02 - Architecture.md` §5.3 (Workflow Engine) & §5.5 (Planner)
- `12 - Mission Profiles.md` (per-mission pipelines)
- `17 - Error Handling Standards.md` (failure taxonomy & recovery)
- `18 - Logging Standards.md` (trace/span contract)
