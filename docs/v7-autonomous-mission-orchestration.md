# Autonomous Mission Orchestration Engine (Sprint 032)

> **Status**: Ratified
> **Wave**: 32
> **Contract**: `capabilities/autonomous-mission-orchestration.json`
> **Engine**: `hunterx.engines.mission_orchestration.engine.MissionOrchestrationEngine`

Sprint 032 makes HunterX capable of executing a **complete security assessment
as a dynamic reasoning-driven mission** rather than a static sequence of
commands:

```
UNDERSTAND TARGET → BUILD TARGET MODEL → DISCOVER ATTACK SURFACE →
CLASSIFY ASSETS → GENERATE HYPOTHESES → SELECT TOOLS → EXECUTE ACTIONS →
INTERPRET RESULTS → UPDATE TARGET MEMORY → CORRELATE EVIDENCE →
GENERATE NEW HYPOTHESES → VALIDATE FINDINGS → PROVE IMPACT →
GENERATE / VALIDATE PoC → REASSESS TARGET → DISCOVER NEW ATTACK PATHS →
REPEAT → FINALIZE MISSION
```

This is **not** a linear workflow engine. It is a **stateful, adaptive,
evidence-driven, reasoning-driven, tool-aware, target-aware mission
orchestrator** built on top of the Sprint 027 Adaptive Mission & Attack-Path
Planning engine and the Sprint 026 target-intelligence layer.

---

## 1. Core mission concept

The orchestration layer reuses the Sprint 027 planning aggregate
(`AdaptiveMission`) as the executable mission — **existing domain models are
never duplicated**. On top of it the orchestrator adds the reasoning/evidence
state that drives the adaptive loop:

| Concept | Location | Role |
|---|---|---|
| `Mission` / `MissionState` | `domain/adaptive_mission_planning` | planning aggregate + lifecycle state |
| `MissionContext` | `domain/mission_orchestration/models.py` | persistent target-centric context (assets, services, endpoints, parameters, evidence, hypotheses, decisions, objectives, history) |
| `MissionObjective` | `domain/mission_orchestration/objective.py` | sprint objective vocabulary mapped onto ratified planning objectives |
| `MissionScope` | `models.py` | immutable authorized scope |
| `MissionStrategy` | `enums.py` (`StrategyKind`) | breadth/depth/risk/asset/technology/vulnerability/evidence/coverage/hypothesis-first + adaptive |
| `MissionPhase` | `enums.py` | canonical orchestration phase |
| `MissionObservation` | `models.py` | atomic normalized tool result |
| `MissionHypothesis` | `models.py` | evidence-driven hypothesis with full status lifecycle |
| `MissionDecision` | `models.py` | explainable decision (NEXT_ACTION/REASON/EXPECTED_RESULT/PRIORITY/DEPENDENCIES/ALTERNATIVES) |
| `MissionCheckpoint` | orchestrator | full resumable snapshot |
| `MissionBranch` | `models.py` | ranked mission branch |
| `MissionOutcome` / `MissionRun` | `models.py` | final outcome / execution run |
| `MissionBudget` / `MissionPolicy` | `models.py` | resource budget / mission intent configuration |

## 2. Mission lifecycle

The mission lifecycle reuses the Sprint 027 `MissionState` machine
(`created → scoping → discovery → enumeration → mapping → analysis →
hypothesis_generation → validation → proof → reassessment → reporting →
completed`, plus `paused / blocked / failed / cancelled`). The orchestrator
additionally tracks a canonical `MissionPhase`:
`TARGET_MODELING → RECONNAISSANCE → ENUMERATION → ATTACK_SURFACE_MAPPING →
TECHNOLOGY_ANALYSIS → VULNERABILITY_DISCOVERY → HYPOTHESIS_ANALYSIS →
VALIDATION → PROOF → IMPACT_ANALYSIS → CORRELATION → REASSESSMENT →
REPORTING`.

States are persisted in the TIDB (`tidb_mission_orchestrations`).

## 3. Mission context

`MissionContext` carries references to the mission, target, scope, assets,
technologies, services, endpoints, parameters, credentials/contexts (where
authorized), observations, findings, hypotheses, evidence, PoCs, tool
executions, attack paths, previous decisions, current phase, current
objectives, remaining objectives, resource state and mission history. It is the
single place the orchestrator reads "what do we know about the target".

## 4. Target-centric memory

Every observation updates the Target Intelligence Database, Target Memory,
Knowledge Graph, asset/technology/service/endpoint/parameter inventory, finding
history, evidence history, tool-execution history and mission history. The
system remembers **what was tested, when, with which tool, with which version,
with which input, what was found, what was not found, what failed, and what
remains unknown** — the TIDB is the source of truth, never transient memory.

## 5–6. Objectives and strategy

Objectives (`full_security_assessment`, `bug_bounty_hunt`, `pentest`,
`red_team_assessment`, `web_application_assessment`, `api_assessment`,
`cloud_assessment`, `external_attack_surface`, `internal_assessment`,
`vulnerability_research`, `targeted_vulnerability_test`) map onto the ratified
planning objectives and influence strategy through the decision-engine weights.
The default strategy is **adaptive**; the other nine strategies are available
and never override scope or safety.

## 7–8. Planner and adaptive execution

The deterministic planner produces an initial plan (target → passive recon →
active enumeration → DNS → ports → HTTP → technology → crawling → parameters →
vulnerability discovery → specialized testing → validation → proof). After
**every** meaningful result the orchestrator:

1. Parses the result. 2. Normalizes it. 3. Updates target state. 4. Updates
evidence. 5. Updates hypotheses. 6. Recalculates the attack surface.
7. Determines knowledge gaps. 8. Determines candidate actions. 9. Ranks them.
10. Selects the next action.

It **never blindly continues a static DAG**.

## 9–10. Decision engine and information gain

`MissionDecisionEngine` consumes the current mission state, target state,
observations, findings, hypotheses, evidence, tool availability, previous
actions, coverage, unknowns, risk, expected information gain and resource cost,
and produces `NEXT_ACTION / REASON / EXPECTED_RESULT / PRIORITY /
DEPENDENCIES / ALTERNATIVES`. Ranking combines expected information gain,
attack-surface expansion, finding-validation potential, evidence improvement,
hypothesis discrimination, coverage improvement, cost, previous failures and
tool reliability. This **prevents random tool execution**.

## 11. Hypothesis loop

`HypothesisLoopEngine` implements the central loop:
`OBSERVE → HYPOTHESIZE → TEST → OBSERVE → UPDATE HYPOTHESIS → TEST → VERIFY →
PROVE`. A hypothesis transitions through `PROPOSED / SUPPORTED /
WEAKLY_SUPPORTED / REFUTED / INCONCLUSIVE / VALIDATED / DISPROVED /
NOVEL_BEHAVIOR`. Verification is required before `VALIDATED`; a proof can never
bypass validation.

## 12. Novel vulnerability discovery

`NovelPipelineStage` implements the experiment loop for behavior that matches
no known signature: `UNKNOWN_BEHAVIOR → BEHAVIORAL_MODEL → HYPOTHESIS →
EXPERIMENT → OBSERVATION → NEW_HYPOTHESIS → MINIMAL_PROOF → VALIDATED_BEHAVIOR`.
Results are classified as `KNOWN / VARIANT / MISCONFIGURATION /
APPLICATION_SPECIFIC / NOVEL_CANDIDATE / NOVEL_VALIDATED`.

## 13–14. Attack-surface graph and attack paths

The orchestrator consumes the attack-surface graph through the Sprint 027
`AttackPathEngine` (paths never directly trigger execution — the planner
translates intelligence into authorized actions). The target-centric context
keeps the graph relationships (target → domain → subdomain → IP → port →
service → technology → application → endpoint → parameter → behavior → finding
→ evidence → PoC) available for new-path discovery.

## 15–16. Tool selection and multi-tool reasoning

Tool selection reuses Sprint 031 Tool Intelligence via the Sprint 027
`ToolSelectionEngine`. The orchestrator never selects tools by hardcoded chains
alone: it asks what is known, what is unknown, which capability reduces
uncertainty, which tool provides it, which tool has the best expected evidence,
which is complementary, and which can validate the hypothesis. Multi-tool
reasoning example: Nuclei detects possible SQLi → SQLi hypothesis → identify
parameter → inspect endpoint → select SQLmap/Ghauri → compare results → analyze
behavior → minimal proof → PoC replay → validated finding. **Nuclei alone is
not a report.**

## 17. Evidence-first findings

A finding evolves through `CANDIDATE → SUPPORTED → VERIFIED → PROVEN →
REPORT_READY`. A vulnerability scanner result alone is a `CANDIDATE`, never
`REPORT_READY`.

## 18. Proof engine integration

The orchestration layer integrates the existing PoC/proof architecture:
`Finding Candidate → Proof Strategy → Minimal Test → PoC Generation → PoC
Execution → Replay → Evidence Capture → Impact Assessment → Finding
Validation`. It uses the existing `VulnerabilityFindingService` / proof
services as the validation/proof substrate.

## 19. Confidence engine

`ConfidenceEngine` aggregates deterministic evidence components — detection
evidence, behavioral evidence, independent verification, impact evidence,
reproducibility, tool reliability, evidence quality, corroboration and
historical target behavior — into a weighted, explainable score. Confidence is
**never an AI probability**.

## 20. False-positive reduction

When a candidate appears, the orchestrator identifies evidence requirements,
selects an independent validator, attempts reproduction, compares baseline and
control, inspects response differences and evaluates alternative explanations
before elevating confidence.

## 21. Negative evidence

`NegativeEvidenceEngine` records `tested / not_vulnerable /
not_reproducible / blocked / inconclusive / not_applicable / not_tested` with
exact tool, version, input hash, conditions and outcome. **"Not found" never
means "not vulnerable"** — negatives are bounded observations that prevent
blind re-testing.

## 22–23. Baseline engine and differential testing

`BaselineEngine` maintains baselines for HTTP, DNS, TLS, authentication,
response codes, headers, content, timing, parameters and application behavior.
`DifferentialTestEngine` compares a test request against a matching baseline
and classifies the delta: status change, length change, header change,
reflection, timing, callback, error behavior or content mutation.

## 24–25. Mission branching and parallel execution

`BranchManager` forks ranked branches when an observation opens multiple paths;
each branch keeps its hypothesis, state, evidence, actions, cost and outcome.
Parallel execution reuses the Sprint 027 execution graph (`parallel_groups`):
independent actions run concurrently, dependent actions wait.

## 26–27. Checkpointing and resume

A checkpoint captures the complete resumable state (planning, observations,
hypotheses, decisions, branches, negative evidence, baselines, trace, coverage,
context). `resume_from_checkpoint` restores the mission — no target state, tool
history, evidence, hypotheses, decisions, findings, branches or PoCs are lost.

## 28. Failure recovery

Tool failures are classified and managed by the Sprint 027 recovery engine
(retry / retry differently / replace tool / change strategy / pause / replan).
A single tool failure never terminates the mission.

## 29. Resource-aware orchestration

`MissionBudget` tracks CPU, memory, network, disk, execution count,
concurrency, time and tool cost. The policy engine blocks actions when the
budget is exhausted; stop conditions fire on resource/time exhaustion.

## 30–31. Coverage engine and knowledge gaps

`MissionCoverageEngine` tracks assets, ports, services, technologies,
endpoints, parameters, vulnerability classes tested, validated findings,
unknown areas and untested attack paths — per (asset × capability) cell, never
"number of tools executed". `KnowledgeGapEngine` answers: what do we know, what
do we not know, what could change our conclusion, and which action would reduce
that uncertainty.

## 32–33. Credential/session contexts and authorization boundary

Multiple authorized contexts (anonymous, authenticated user, privileged user,
API token, application session, cloud identity) are tracked independently in
`MissionContext.contexts` — evidence is never mixed between contexts. Every
action receives the mission context, target context, scope context and
execution policy; the policy engine prevents accidental cross-target state
contamination.

## 34. Target database is the source of truth

All assets, observations, findings, evidence, tool executions, hypotheses,
decisions, attack paths, timestamps and provenance are persisted in the TIDB.
The orchestrator never treats transient memory as authoritative.

## 35–36. Event-driven orchestration and telemetry

The orchestrator emits the typed `mission.*` event vocabulary (started, phase
started/completed, action selected/started/completed, observation created,
hypothesis created/updated, finding created/validated, proof started/completed,
attack_path created, branch created, checkpoint created, reassessment started,
completed). `MissionTelemetry` tracks decision latency, tool utilization,
finding yield, validation yield, false-positive rate, coverage, evidence
quality, branch efficiency, resource utilization, failed actions and fallback
rate.

## 37–38. Decision explanation and reasoning trace

Every major decision is explainable (`NEXT ACTION / REASON / EXPECTED RESULT /
ALTERNATIVES / WHY NOT`). `ReasoningTrace` persists **structured** reasoning
metadata (observation → hypothesis → decision → evidence → action → result →
rationale) as an auditable reasoning graph — it never stores hidden
chain-of-thought.

## 39–40. AI planner and deterministic validation

AI may generate hypotheses, rank actions, interpret ambiguous results, suggest
attack paths, identify missing evidence, suggest validators and suggest
alternative explanations — but the deterministic components enforce schema,
state transitions, tool contracts, scope, persistence and evidence provenance.
`AI → Candidate Decision → Decision Validator → Policy/Scope Validator → Tool
Capability Validator → Mission State Validator → Execution`. **AI never
directly executes arbitrary commands.**

## 41–42. Mission policies and stop conditions

`MissionPolicy` defines objective, scope, allowed techniques, resource limits,
time limits, authentication contexts, validation depth, proof depth, coverage
target and stop conditions — it is mission configuration, never hardcoded into
tools. `MissionPolicyEngine` evaluates stop conditions after every observation:
objectives complete, coverage target achieved, high-value hypotheses resolved,
findings validated, resource/time budget exhausted, operator cancelled or
unrecoverable failure.

## 43–44. Reassessment and finding cascades

After every major validated finding the orchestrator recalculates the attack
surface, updates the graph, generates new hypotheses and continues.
`FindingCascadeEngine` derives follow-on hypotheses (SSRF → internal service
discovery; secret exposure → authorized credential mapping; new API →
authentication/authorization analysis; SQLi → database behavior mapping).

## 45–46. Impact analysis and report-ready gate

`ImpactAnalysisEngine` computes technical impact, affected assets/users, data
exposure potential, privilege boundary, business impact indicators,
exploitability, reproducibility and confidence — only for verified-or-beyond
findings. The Sprint 029 report-ready checklist (title, classification,
affected asset/endpoint/parameter, description, evidence, verification status,
reproduction, PoC, impact, confidence, provenance, timestamps, tool evidence,
validation evidence) gates final reporting.

## 47. Full mission example

The acceptance suite drives an end-to-end mission over a synthetic target
environment (see §52): subdomain discovery → DNS resolution → port discovery →
HTTP probing → technology detection → crawling → URL discovery → parameter
discovery → JS analysis → vulnerability discovery → hypothesis generation →
specialized validation → proof → PoC → replay → impact → correlation →
reassessment → new attack path → validation → report. The workflow is dynamic,
never a predefined script.

## 48–52. Database, API, CLI

- **Database**: 18 normalized TIDB tables (`tidb_mission_orchestrations`,
  `_runs`, `_phases`, `_actions`, `_decisions`, `_hypotheses`, `_branches`,
  `_checkpoints`, `_policies`, `_objectives`, `_coverage`, `_timelines`,
  `_observations`, `_negative`, `_baselines`, `_reasoning`, `_telemetry`,
  `_impact`) with migration `a3f5b7c9d1e3`.
- **API**: `POST /missions`, `GET /missions/{id}`, start/pause/resume/cancel/
  finalize, and read views for state/timeline/decisions/hypotheses/findings/
  attack-paths/coverage/tool-executions plus the reasoning-loop endpoints.
- **CLI**: `hunterx mission create|start|status|pause|resume|cancel|finalize|
  timeline|decisions|hypotheses|findings|attack-paths|coverage|tools`.

## 53. Architecture enforcement

The orchestrator follows Domain → Application → Ports → Adapters →
Infrastructure. Mission orchestration never depends on concrete tool
implementations: it consumes normalized observations and capability-aware
actions through ports (`TidbRepositoryFactory`, `EventBusPort`,
`AdaptiveMissionPlanningEngine`). The architecture test enforces this by
asserting the orchestration layer does not import tool adapter modules.

## 54. Testing

- **Unit**: domain models, hypothesis loop, decision/information-gain,
  baseline/differential testing, negative evidence, coverage, knowledge gaps,
  confidence, branches, telemetry, trace, policies/stop conditions, impact,
  cascade, orchestrator and service.
- **Golden**: `tests/golden/missions/` fixtures with deterministic replay.
- **Acceptance**: full synthetic mission over a synthetic target environment
  containing multiple domains/subdomains/services, HTTP apps, API endpoints,
  parameters, JS endpoints, an intentional vulnerability, a false positive, a
  tool failure, a contradictory tool result, a hidden endpoint and a
  second-order discovery.
- **Security**: adversarial orchestration (missing tool, broken parser,
  unexpected output, duplicate/contradictory/stale/partial results, tool
  timeout, target-state mutation, branch explosion, circular hypotheses, AI
  invalid decisions, invalid tool capability, resource exhaustion, checkpoint
  corruption, resume, parallel race, cross-target contamination).
- **Performance**: 1/10/100 missions, 10k/100k observations, 1k tool
  executions; planner latency stays bounded.
- **Architecture**: layering enforcement.
