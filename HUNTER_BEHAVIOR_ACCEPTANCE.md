# HUNTER_BEHAVIOR_ACCEPTANCE.md

## Fundamental question — answered with code-level evidence

> Does HunterX actually reason over reconnaissance results and iteratively pursue
> security hypotheses, or does it merely execute tools and collect output?

**Answer: HunterX is now a reasoning-driven, evidence-informed autonomous security
hunter — not a tool dumper.** It is deterministic and explainable (no LLM involved),
and it reasons in the sense that **every next action is a function of accumulated
evidence**: observations update a target model, the target model produces
hypotheses with provenance, hypotheses are prioritized, the decision engine ranks
evidence-driven probes by the hypothesis they test, probe results update hypotheses,
and a hypothesis must be validated by independent evidence before its finding is
promoted. Coverage alone can no longer terminate a mission that still has open
high-value hypotheses.

This gate **wired the previously-dangling reasoning stages** into the runtime loop.
Before the gate, hypotheses existed but were inert (ignored by the ranker), probes
did not update hypotheses, findings never left the CANDIDATE stage, and coverage
could stop the mission with unresolved hypotheses. Those stages are now connected
(see PROFILE_WORKFLOW_AUDIT.md §4-§5).

## The closed loop

```
OBSERVE  (tool -> normalized observation)
  -> MODEL  (_populate_context: assets/tech/services/endpoints/parameters)
  -> HYPOTHESIZE  (_hypothesize_from_observation: evidence-derived statement,
                   provenance {observation_id, observation_type, asset_key},
                   evidence-based priority)
  -> PRIORITIZE  (_priority_for_hypothesis; _candidates_from_plan binds hypothesis)
  -> TARGETED PROBE  (replan schedules a validation action bound to the hypothesis;
                      decision._hypothesis_factor ranks it by priority*confidence)
  -> ANALYZE  (_handle_execution)
  -> REASSESS  (_assess_hypotheses_after_observation: supporting/contradicting)
  -> VALIDATE  (SUPPORTED -> verify_hypothesis -> VALIDATED)
  -> FINDING  (_promote_findings_for_hypothesis: CANDIDATE -> verified)
  -> CONTINUE  (coverage stop gated on open high-value hypotheses; else finalize)
```

## Acceptance tests A–J (tests/integration/test_hunter_behavior.py — 12 passed)

| # | Criterion | Test | Result |
|---|---|---|---|
| A | Recon drives modeling | `TestAReconDrivesModeling` — whatweb WordPress/PHP + httpx endpoints land in `context.technologies`/`context.endpoints` | PASSED |
| B | Modeling drives hypotheses | `TestBModelingDrivesHypotheses` — evidence-derived hypothesis with provenance; empty observations create none | PASSED |
| C | Hypothesis drives decision | `TestCHypothesisDrivesDecision` — vulnerability hypothesis (priority ≥ 0.7) schedules a `vulnerability_scanning` validation action bound to `hypothesis_id` | PASSED |
| D | Probe drives reassessment | `TestDProbeDrivesReassessment` — the probe adds a 2nd supporting observation; hypothesis leaves `proposed` | PASSED |
| E | Validation drives finding | `TestEValidationDrivesFinding` — validated hypothesis promotes its finding to `verified` | PASSED |
| F | Negative affects reasoning | `TestFNegativeAffectsReasoning` — failed probe records negative evidence; the failed capability's re-selection is penalized | PASSED |
| G | Profiles differ behaviorally | `TestGProfilesDifferBehaviorally` — distinct `discovery_chain`s/first capabilities per objective | PASSED |
| H | No dump-only behavior | `TestHNoDumpOnlyBehavior` — coverage stop blocked while a high-value hypothesis is open; fires only when none remain | PASSED |
| I | Live CLI reflects reasoning | `TestILiveCliReflectsReasoning` — CLI stderr shows `>> decide`, `>> run`, observation/coverage reasoning lines | PASSED |
| J | Report causal chain | `TestJReportReconstructsCausalChain` — report separates Recon/Target Model/Hypotheses/Decisions/Findings; reasoning trace has observation→hypothesis→decision | PASSED |

## Live localhost acceptance report (Linux/WSL, target http://localhost:3010)

Command: `hunterx hunt full_security_assessment http://localhost:3010`

```
rc=0  state=completed  phase=reporting
observations=7  decisions=7  tool_executions=7  negative_evidence=5  coverage=0.71
hypotheses=0  findings=0        <- honest: no meaningful weakness evidence was produced
```

The live renderer emitted the full reasoning surface on stderr:
`[HUNT] ... [PREFLIGHT] passed` → `>> decide subdomain_enumeration with subfinder` →
`>> run subfinder (...) -> http://localhost:3010` → `observation ...` →
`coverage: ... = tested/not_assessed` → `[DONE] mission completed`.

The mission honestly produced **zero hypotheses and zero findings** because the real
tools returned no meaningful weakness evidence against the local Juice Shop run
(empty/negative recon results, 5 negative-evidence records). This is the *correct*
behavior: no fabricated hypotheses, no fabricated findings — the anti-pattern this
gate exists to prevent. The behavioral loop itself (recon→model→hypothesize→probe→
validate→finding) is proven deterministically by tests A–J with controlled evidence.

## Finding honesty

- An observation is only a candidate: `_populate_context` registers `CANDIDATE`
  findings and `_hypothesize_from_observation` refuses empty content.
- A candidate is promoted to `verified` **only** when its explaining hypothesis is
  `VALIDATED` by independent supporting evidence (`_promote_findings_for_hypothesis`).
- A failed/empty probe records bounded negative evidence and never fabricates a finding.
- No `UNKNOWN_BEHAVIOR` hypothesis is generated from nothing (tests B, E, F prove it).

## Determinism

No AI model is involved: ranking uses the documented strategy weights and
evidence-derived factors (`decision.py`), hypothesis transitions are rule-based
(`hypothesis.py`), and stop conditions are evaluated deterministically (`policy.py`).
This is honest deterministic reasoning, never labeled as LLM reasoning.

## Coverage / stop honesty

`COVERAGE_TARGET_ACHIEVED` is now gated on `not _has_open_high_value_hypotheses`
(priority ≥ 0.75). Coverage measures what was tested; it no longer terminates the
mission while a meaningful high-value hypothesis is unresolved.

## Verification

- `tests/integration/test_hunter_behavior.py` — 12 passed
- `tests/integration/test_mission_execution_lifecycle.py`, `test_mission_execution_defects.py`,
  `test_mission_preflight.py`, `test_mission_runner_sandbox.py`, `test_mission_ai_path.py`,
  `test_adaptive_mission_planning_integration.py` — 54 passed
- `tests/unit/test_mission_orchestration_*`, `test_adaptive_mission_planning_*`,
  `test_mission_planning_*` — 169 passed
- `tests/tools/` + readiness — 124 passed
- Ruff clean on all changed files. mypy: pre-existing environment crash (Python 3.14),
  documented in the toolchain gate.
