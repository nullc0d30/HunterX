# Adaptive Mission & Attack-Path Planning (Sprint 027)

> **Status**: Ratified
> **Wave**: 27
> **Contract**: `capabilities/adaptive-mission-planning.json`
> **Engine**: `hunterx.engines.adaptive_mission_planning.engine.AdaptiveMissionPlanningEngine`

Sprint 027 transforms HunterX from a *planner of command lists* into an
**adaptive security assessment system**. Target intelligence, the
attack-surface graph, coverage, unknowns, hypotheses, tool capabilities,
proof requirements and the mission objective are turned into a **living
execution graph** — a dynamic, explainable, continuously re-plannable mission.

The mission is **not** a static list of commands. The fundamental loop is:

```
MISSION OBJECTIVE → CURRENT INTELLIGENCE → CURRENT COVERAGE → UNKNOWNS →
HYPOTHESES → ATTACK PATHS → CANDIDATE ACTIONS → POLICY FILTER →
ACTION RANKING → EXECUTION → OBSERVATION → EVIDENCE → GRAPH UPDATE →
REASSESSMENT → PLAN DELTA → NEXT ACTION
```

The planner continuously answers: *"What is the most valuable authorized
action HunterX can take next, given everything it currently knows?"*

---

## 1. Mission objective model

`MissionObjective` (`domain/adaptive_mission_planning/enums.py`) supports:
`ATTACK_SURFACE_DISCOVERY`, `WEB_SECURITY_ASSESSMENT`,
`API_SECURITY_ASSESSMENT`, `CLOUD_SECURITY_ASSESSMENT`,
`NETWORK_SECURITY_ASSESSMENT`, `VULNERABILITY_DISCOVERY`,
`BUG_BOUNTY_ASSESSMENT`, `PENTEST_ASSESSMENT`, `RED_TEAM_SIMULATION`,
`TARGET_MONITORING`, `FINDING_VALIDATION`, `PROOF_COLLECTION`.

Each objective maps through `default_objective_catalog()` to a
`MissionObjectiveSpec`: coverage priorities, allowed capabilities, validation
depth (`DISCOVERY`/`VALIDATION`/`PROOF`/`IMPACT_DEMONSTRATION`), proof
requirement, risk tolerance and completion criteria.

## 2. Mission constraints

`MissionConstraints` captures scope, authorization context, excluded assets,
excluded capabilities, time/execution budgets, rate limits, concurrency,
risk threshold and proof/credential/network/retention policies. **Scope and
authorization are immutable** — no planner, AI proposal or tool output may
ever override them (`PolicyEngine`).

## 3. Mission state

`MissionState` covers `CREATED → SCOPING → DISCOVERY → ENUMERATION → MAPPING
→ ANALYSIS → HYPOTHESIS_GENERATION → VALIDATION → PROOF → REASSESSMENT →
REPORTING → COMPLETED`, plus `PAUSED`/`BLOCKED`/`FAILED`/`CANCELLED`.
Transitions are explicit and enforced by `domain/adaptive_mission_planning/state.py`.

## 4. Execution graph

`AdaptiveExecutionGraph` (`graph.py`) is a **living DAG of `ActionNode`
entries** (an *action*, never simply a tool invocation — examples:
`DISCOVER_SUBDOMAINS`, `ENUMERATE_DNS`, `IDENTIFY_SERVICES`,
`ENUMERATE_HTTP`, `IDENTIFY_TECHNOLOGY`, `DISCOVER_ENDPOINTS`,
`DISCOVER_PARAMETERS`, `TEST_AUTHORIZATION`, `VALIDATE_HYPOTHESIS`,
`COLLECT_PROOF`, `REPLAY_PROOF`, `GENERATE_FINDING`).

### 5. Action node

`ActionNode` carries `action_id`, `mission_id`, `objective`, `asset`,
`capability`, `tool_candidate_set`, `selected_tool`, `preconditions`,
`depends_on`, `expected_observations`, `expected_information_gain`,
`expected_evidence`, `expected_proof_value`, `hypothesis_id`, `risk`, `cost`,
`timeout_seconds`, `retry_policy`, `stop_conditions`,
`success_conditions`, `failure_conditions`, `scope_requirements`,
`authorization_requirements`, `validation_level`, `status` and `provenance`.

### 6. Dynamic dependencies

`DynamicDependency` supports `depends_on`, `blocks`, `enables`,
`invalidates`, `supersedes`, `alternative_to`, `requires_evidence`,
`requires_observation`, `requires_proof`. The graph is dynamically
modifiable through `apply_delta()`.

### 7. Conditional branching

`ConditionalBranch` supports `IF/THEN/ELSE/GOTO/FORK/JOIN/WAIT_FOR_EVIDENCE/
REPLAN/STOP`. Branches are declarative — no application-specific workflows
are hardcoded.

### 8–9. Parallel & serial execution

`parallel_groups()` identifies waves of independently runnable nodes when
scope, resources, dependencies and risk permit. Actions requiring prior
evidence remain sequential (`topological_order()` honours `DEPENDS_ON`).
The planner never parallelizes actions that could invalidate evidence,
create conflicting state, exceed target limits, violate authorization or
cause unsafe testing.

## 10–12. Replanning, plan delta, plan versioning

`ReplanningEngine` evaluates replanning triggers (`ReplanTrigger`: new asset,
technology, endpoint, parameter, hypothesis, conflicting evidence, proof
failed, scope changed, unknown behavior, ...) and produces a `PlanDelta`
(`ADD_ACTION`, `REMOVE_ACTION`, `MODIFY_ACTION`, `REORDER_ACTION`,
`PAUSE_ACTION`, `RESUME_ACTION`, `REPLACE_TOOL`, `CHANGE_PRIORITY`,
`CREATE_BRANCH`, `MERGE_BRANCH`, `INVALIDATE_BRANCH`, `MARK_COMPLETE`).

**The full mission is never rebuilt unnecessarily.** Every revision is
captured in a `PlanVersion` (`plan_version`, `parent_version`, `reason`,
`trigger`, `changed_nodes`, `changed_dependencies`, `created_by`,
`decision_provenance`) and the complete planning history is replayable.

## 13–15. Decision engine and information gain

`ActionDecisionEngine` consumes target intelligence, coverage, unknowns,
hypotheses, mission objective, constraints, available tools, tool health,
evidence and proof state, and produces **ranked, policy-filtered candidate
actions**. Scoring (`ScoringModel`) is **explainable**: twelve configurable
factors (information gain, hypothesis relevance, coverage improvement,
evidence value, proof value, asset criticality, mission priority, tool
effectiveness, cost, risk, redundancy, dependency readiness) — never an
opaque AI-only score. Information gain answers *"what uncertainty will this
action remove?"*.

## 16–18. Hypothesis- and proof-aware planning

If a hypothesis exists, the planner maximizes the probability of validating
or disproving it (e.g. SSRF → identify request primitive → controllable
parameter → validation strategy → controlled evidence → correlate callback →
minimal proof → validate). Proof is a first-class objective: candidate
finding → evidence gap → validation action → proof action → proof replay →
validated finding. A finding never becomes reportable merely because a
scanner reported it.

## 19. Safe validation

All validation/proof actions respect authorized scope, minimal-impact
policy, rate limits, target safety, proof policy, credential restrictions,
the execution sandbox and controlled callback infrastructure. The planner
distinguishes `DISCOVERY`/`VALIDATION`/`PROOF`/`IMPACT_DEMONSTRATION` and
never automatically escalates from discovery to destructive exploitation.

## 20–22. Tool selection, tool chains, feedback loop

Tool selection integrates Sprint 025 (`ToolSelectionEngine` over the
`ToolMasteryAPI`), selecting on capability, target compatibility, health,
cost, risk, evidence quality and proof compatibility. `ToolChainPlanner`
generates capability-driven chains dynamically (e.g. Subfinder → DNSx →
HTTPx → Katana → Arjun → hypothesis → validation → proof), but the exact
chain emerges from target state, objective, coverage gaps, hypotheses and
tool capabilities — **no universal hardcoded pipeline**. Every tool execution
feeds raw artifact → parser → normalizer → observation → evidence → graph →
coverage → hypothesis engine → planner, so the planner never operates on
stale target state.

## 23–24. Failure recovery and tool fallback

`FailureClassifier` classifies failures (`TIMEOUT`, `RATE_LIMIT`,
`NETWORK_ERROR`, `AUTH_ERROR`, `INVALID_INPUT`, `TARGET_CHANGED`,
`TOOL_ERROR`, `PARSER_ERROR`, `RESOURCE_LIMIT`, `POLICY_BLOCK`, `UNKNOWN`);
`RecoveryEngine` selects retry / retry differently / replace tool / change
strategy / pause / mark unavailable / replan. `ToolFallbackResolver`
substitutes capability-equivalent tools only — never blindly (Nmap →
RustScan/Masscan where appropriate).

## 25–27. Resource/time-aware planning and checkpointing

`ResourcePlanner` understands concurrency, budgets and tool limits and avoids
redundant tool launches. `TimePlanner` supports deadlines, time budgets,
priority windows, scheduled reassessment, long-running tasks and
pause/resume. `CheckpointEngine` + `PlanCheckpoint` persist mission state,
plan version, execution graph, completed/pending actions, observations,
evidence, hypotheses, proof states and tool state so a mission resumes after
restart **without losing intelligence**.

## 28–32. Target change, conflicts, negatives, unknowns, novel paths

Target-change triggers (Sprint 026 history) drive replanning. Conflicting
evidence creates a resolution branch (re-test, timestamps, environment).
Negative results are **bounded observations** — never universal absence.
`UNKNOWN_BEHAVIOR` creates an investigation branch
(UNKNOWN → CHARACTERIZE → HYPOTHESIS → EXPERIMENT → OBSERVE → REFINE →
VALIDATE → PROVE/DISPROVE) that does **not** require a CVE/CWE/signature.

## 33–36. Mission modes

`MissionMode` supports `FAST`, `BALANCED`, `DEEP`, `STEALTH`,
`COVERAGE_FIRST`, `EVIDENCE_FIRST`, `PROOF_FIRST`, `BUG_BOUNTY`, `PENTEST`,
`RED_TEAM_SIMULATION`. Modes modify priorities via additive score weights —
they never override authorization or safety.

## 37–40. Attack paths and graph separation

`AttackPathEngine` identifies security-relevant chains (Internet → exposed
asset → service → application → authentication boundary → authorization
weakness → sensitive resource; cloud exposure → credential/config exposure →
reachable service → validated weakness). Paths are scored with explainable
dimensions (`reachability`, `evidence_strength`, `asset_criticality`,
`assumption_count`, `validation_state`, `proof_availability`, `risk`,
`objective`). States are **never collapsed**:
`HYPOTHETICAL → SUPPORTED → VALIDATED → PROVED`.

Three graphs are kept strictly separate:
- **AttackSurfaceGraph** — what exists / what relationships are observed.
- **AttackPathGraph** — possible security-relevant paths (intelligence only).
- **ExecutionGraph** — what HunterX is actually authorized to execute.

The attack graph **never directly triggers execution**; the planner translates
intelligence into authorized actions.

## 41–43. Explainability and deterministic fallback

Every decision answers WHY THIS ACTION / WHY NOW / WHY THIS TOOL / WHAT
INFORMATION / WHAT HYPOTHESIS / WHAT EVIDENCE / WHAT PROOF / ALTERNATIVES
(`DecisionRecord`). AI is advisory and policy-bounded; it cannot execute
arbitrary commands, expand scope, override safety, declare proof without
evidence, or mark a finding validated without validation. `DeterministicPlanner`
keeps the system fully functional without AI (asset discovery, coverage
completion, hypothesis validation, proof completion, recovery, replanning,
unknown-behavior investigation).

## 44–45. Events and persistence

Typed events: `mission.plan.created`, `mission.plan.revised`,
`mission.action.proposed`, `mission.action.approved`, `mission.action.started`,
`mission.action.completed`, `mission.action.failed`, `mission.replan.triggered`,
`mission.path.discovered`, `mission.path.validated`, `mission.proof.required`,
`mission.proof.completed`, `mission.checkpoint.created`, `mission.resumed` —
all with provenance.

Persistence uses **TIDB** normalized entities (never unbounded JSON blobs):
`tidb_adaptive_missions`, `_action_nodes`, `_dependencies`, `_branches`,
`_plan_versions`, `_plan_deltas`, `_decisions`, `_attack_paths`, `_gaps`,
`_checkpoints`, `_failures`, `_tool_fallbacks`, `_tool_selections`
(migration `1b3d5f7a9c2e`).

## 46–47. API and CLI

Application services (`AdaptiveMissionPlanningService`,
`AdaptiveMissionPlanningQueryService`) expose create/get plan/plan
history/candidates/approve/pause/resume/replan/attack paths/explain/coverage/
evidence gaps/proof gaps. FastAPI routes live under `/missions/adaptive`.
CLI commands: `hunterx mission plan`, `mission status`, `mission replan`,
`mission pause`, `mission resume`, `mission paths`, `mission explain`.

## 48–52. Security, performance, observability

Scope isolation, mission/tenant isolation, authorization, safe-execution
policy, credential boundaries, tool sandbox policy, artifact validation,
prompt-injection resistance and untrusted tool-output handling — **a
malicious tool result never becomes an instruction**. Performance avoids
full-plan rebuilds, full-graph rescans, N+1 queries, duplicate action
generation and unbounded in-memory history. Every action exposes
mission_id/plan_version/action_id/target_id/asset_id/tool/decision_reason/
correlation_id/timestamp/duration/result/evidence_refs via the existing
telemetry/logging.

## 53. Extension points

- New mission objectives → extend `default_objective_catalog()`.
- New capabilities → register tool families in the deterministic candidates
  and the Sprint 025 arsenal.
- New ranking policies → new `ScoringModel` weights / mission-mode entries.
- New replanning triggers → extend `ReplanTrigger` and `ReplanningEngine`.
- New attack-path kinds → extend `_KIND_TO_STEP` in `attack_path.py`.
- Persistence is additive: new normalized TIDB entities auto-register via
  the entity/model registry.

## 54. Testing

Unit, component, integration, golden, architecture, security, performance and
acceptance suites cover the 15 required scenarios (static plan creation, new
asset replan, hypothesis replan, tool fallback, conflict investigation, proof
gap creation, proof closure, scope restriction, AI forbidden-action rejection,
restart resume, safe parallel execution, conditional branching, attack path
discovered-but-not-executed, unknown-behavior investigation, bounded negative
results) plus the golden end-to-end test against a controlled synthetic
target where the exact tool sequence is **not** hardcoded.
