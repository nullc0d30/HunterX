# PROFILE_WORKFLOW_AUDIT.md — HunterX Profile & Workflow Audit

Platform: Linux/WSL · Source: `src/hunterx` · Audit date: 2026-08-16

## 0. Headline answer

HunterX's `hunt` loop is **not** a static "run tool A → B → C → dump" pipeline, and it is
**not** yet a full reasoning engine. Before this gate it was a *dependency-ordered execution
of a deterministic per-objective plan with an evidence-grounded journal*: observations did
update the target model, hypotheses were created from real observation content, but
**hypotheses did not drive the next decision, probes did not advance hypotheses, findings
never left the CANDIDATE stage, and coverage could terminate the mission while high-value
hypotheses were unresolved.** This gate wired those stages so the loop is now genuinely
**Observe → Model → Hypothesize → Prioritize → Targeted Probe → Reassess → Validate →
Finding** (see HUNTER_BEHAVIOR_ACCEPTANCE.md for the live/unit proof).

The five profile names from the brief (`bugbounty`, `bug_hunter`, `pentester`,
`red_teamer`, `real_world_hacker`) **do not exist** in the codebase. The real profile /
objective vocabulary is enumerated below; the behavior matrix maps it.

---

## 1. Profiles — what actually exists

| Brief name | Exists in code? | Real identifier | Behavioral carrier |
|---|---|---|---|
| bugbounty | No | `bug_bounty_assessment` / `bug_bounty_hunt` (objective), `bug-bounty` (mission_type), `MissionProfile.BUG_BOUNTY` | `MissionObjectiveSpec`, `discovery_chain`, `SafetyPolicy._PROFILE_LIMITS` |
| bug_hunter | No | — | — (no such profile; closest: `vulnerability_discovery` objective) |
| pentester | No | `pentest_assessment` / `pentest` (objective), `pentest` (mission_type), `MissionProfile.PENTEST` | `MissionObjectiveSpec`, `discovery_chain` |
| red_teamer | No | `red_team_simulation` / `red_team_assessment` (objective), `red-team` (mission_type), `MissionProfile.RED_TEAM` | `MissionObjectiveSpec`, `discovery_chain` |
| real_world_hacker | No | — | — (no such profile) |

- **`MissionProfile` enum** — `src/hunterx/domain/vulnerability_validation/enums.py:123`:
  `BUG_BOUNTY`, `PENTEST`, `RED_TEAM`, `SECURITY_ASSESSMENT`. They differ only in
  concurrency/rate-limit ceilings (`_PROFILE_LIMITS`, `vulnerability_validation/safety.py:37-42`).
- **`MissionObjective` enum** — `src/hunterx/domain/adaptive_mission_planning/enums.py:19`.
- **`MissionObjectiveSpec` catalog** — `src/hunterx/domain/adaptive_mission_planning/objective.py:22-317`
  is the single source of truth: allowed capabilities, validation depth, proof requirement,
  risk tolerance, completion criteria per objective.
- **`discovery_chain`** — `src/hunterx/domain/adaptive_mission_planning/catalog.py:22-83`:
  per-objective ordered capability tuple that becomes the initial plan.
- **`hunterx hunt <X> <target>`** treats `<X>` as an **objective name**
  (`_OBJECTIVE_MAP`, `domain/mission_orchestration/objective.py:18-42`); unknown names
  silently fall back to `attack_surface_discovery` (objective.py:52).
- The runtime tool-selection `mission_type` is **hardcoded `"bug-bounty"`** at the
  composition root (`platform/assembler.py:816,838`), so objective does not currently change
  the TIP authorization ceiling (out of scope for this gate).

## 2. Profile → behavior matrix

See `PROFILE_BEHAVIOR_MATRIX.json` for the machine-readable version. Key per-objective
differences (initial capability chain, validation depth, proof):

| Objective | Initial `discovery_chain` | Validation depth | Proof | Reportability bias |
|---|---|---|---|---|
| `attack_surface_discovery` | subdomain → dns → port → service → tech → cert → endpoint | discovery | none | attack-surface breadth |
| `bug_bounty_assessment` | endpoint → parameter → vulnerability_scanning | proof | minimal | web/API attack surface |
| `pentest_assessment` | asset → endpoint → parameter → vulnerability_scanning | validation | minimal | systematic coverage |
| `red_team_simulation` | asset → endpoint → authorization_analysis | validation | minimal | objective-driven access |
| `vulnerability_discovery` | endpoint → parameter → vulnerability_scanning | validation | minimal | broad discovery |
| `api_security_assessment` | endpoint → parameter → vulnerability_scanning | validation | minimal | API surface |

## 3. Execution graph trace (`hunterx hunt <objective> <target>`)

```
CLI _hunt (cli/commands.py:398) 
  -> MissionOrchestrationService.create_mission (application/mission_orchestration.py:71)
    -> MissionOrchestrator.create_mission (domain/mission_orchestration/orchestrator.py:147)
      -> resolve_objective (objective.py:45)            [silent fallback on unknown]
      -> DeterministicMissionPlanner.create_initial_plan (adaptive_mission_planning/mission.py:166)
           = per-objective discovery_chain as linear DEPENDS_ON ActionNodes
  -> MissionOrchestrationService.start
  -> MissionExecutionService.run (application/mission_execution.py:233)
    per cycle (max_cycles, 3-idle cap):
      _approve_ready_actions -> decide_next -> _execute_decision -> engine.execute
      -> _handle_execution (mission_execution.py:439):
           ingest_result (orchestrator.py:333):
             add_observation -> _populate_context (target model) -> _hypothesize_from_observation
           _assess_hypotheses_after_observation (NEW: probe updates hypothesis, validates, promotes finding)
           _replan_from_observation (NEW: binds hypothesis_id to the validation action)
      -> _orchestration.stop_condition (policy.py:80)   [NEW: coverage gated on open high-value hypotheses]
  -> _finalize_run (state -> completed, outcome record)
```

## 4. Stage-by-stage audit (before → after this gate)

| Stage | Before | After | Where |
|---|---|---|---|
| Observe | ✓ tool execution + normalized observation | ✓ unchanged | `_handle_execution` |
| Understand/Normalize | ✓ `_observation_from_result`, `_normalize_content` | ✓ unchanged | `mission_execution.py:735`, `orchestrator.py:357` |
| Correlate | ✓ `_populate_context` target model (assets/tech/services/endpoints/params) | ✓ unchanged | `orchestrator.py:1048-1125` |
| Build Target Model | ✓ | ✓ | `context` maps |
| Generate Hypotheses | ✓ evidence-derived statements | ✓ + **evidence-based priority** (`_priority_for_hypothesis`) + **provenance** (observation_id/type/asset) | `orchestrator.py:989-1046`, NEW `_priority_for_hypothesis` |
| Prioritize | ⚠ hypotheses existed but were inert (priority 0.5, ignored by ranker) | ✓ hypothesis priority now feeds the decision factor | `decision.py:_hypothesis_factor` (NEW) |
| Select Next Action | ⚠ ranked by static constants only | ✓ hypothesis-bound validation actions are ranked by the hypothesis's priority/confidence | `_candidates_from_plan` + `decision.py` |
| Execute Targeted Probe | ⚠ validation nodes had empty `hypothesis_id` | ✓ replan binds the hypothesis (`_replan_from_observation` detail) | `mission_execution.py:805` |
| Analyze Result | ✓ | ✓ | `_handle_execution` |
| Reassess | ⚠ hypotheses never updated by probe results | ✓ `_assess_hypotheses_after_observation` updates supporting/contradicting evidence | NEW |
| Validate | ✗ never wired into the loop | ✓ hypothesis → SUPPORTED → verify → VALIDATED | `_assess_hypotheses_after_observation` |
| Produce Evidence / Finding | ✗ findings stayed CANDIDATE forever | ✓ validated hypothesis promotes CANDIDATE finding → `verified` | `_promote_findings_for_hypothesis` (NEW) |
| Finding / Attack Path | ✓ candidate findings + attack-path graph (intelligence only) | ✓ (attack paths out of this gate's scope) | `orchestrator.py:851` |
| Continue when justified | ✗ coverage could stop with open high-value hypotheses | ✓ coverage stop gated on no open high-value hypotheses | `policy.py:_has_open_high_value_hypotheses` (NEW) |
| Finalize | ✓ `_finalize_run` | ✓ unchanged | `mission_execution.py` |

## 5. Gaps fixed (smallest correct changes)

1. **`add_hypothesis` dedup now merges supporting evidence** (`orchestrator.py:452`) — previously
   the same-statement hypothesis never accumulated independent observations (broke validation
   and caused duplicate probing).
2. **`CandidateAction.hypothesis_id` + decision factor** (`decision.py`) — the ranker now boosts
   a probe bound to an open high-priority hypothesis, so the next action depends on what HunterX
   knows.
3. **Replan binds `hypothesis_id`** (`_replan_from_observation`) and dedups per-hypothesis
   (not per-capability), so a vulnerability observation schedules a targeted validation probe.
4. **Loop validation**: `_assess_hypotheses_after_observation` updates the hypothesis from the
   probe result, verifies when SUPPORTED, and promotes the linked CANDIDATE finding to `verified`
   (`_promote_findings_for_hypothesis`). Finding honesty preserved: promotion requires a validated
   hypothesis.
5. **Coverage stop gate** (`policy.py`) — `COVERAGE_TARGET_ACHIEVED` cannot fire while a
   high-value (priority ≥ 0.75) hypothesis is unresolved; the mission continues (or finalizes
   honestly when the plan/budget is exhausted).
6. **Evidence-based hypothesis priority** (`_priority_for_hypothesis`) so vulnerability-class
   hypotheses are high-value and drive decisions / block premature stopping.

## 6. Remaining honest limitations (not fixed in this gate, by scope)

- Attack-path construction, impact/proof/cascade, novel-behavior pipeline, and per-profile
  mission_type authorization are out of scope (noted as future work).
- `OBJECTIVES_COMPLETE` never fires (static `remaining_objectives`); the mission still
  finalizes honestly via plan exhaustion / budget / max-cycles.
- No LLM is involved: ranking is deterministic and explainable (documented, never labeled as AI).
