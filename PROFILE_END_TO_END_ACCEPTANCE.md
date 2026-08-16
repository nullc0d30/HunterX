# PROFILE_END_TO_END_ACCEPTANCE.md

Proves that the real profile/objective identifiers in the codebase change
actual runtime behavior — persisted discovery chains and decision records —
not just a label.

## Profiles tested (real identifiers from `_OBJECTIVE_MAP` / `discovery_chain`)

| Objective | Initial discovery chain | Strategy focus |
|---|---|---|
| `bug_bounty_assessment` | endpoint → parameter → vulnerability_scanning | web/API attack surface |
| `pentest_assessment` | asset → endpoint → parameter → vulnerability_scanning | systematic coverage |
| `red_team_simulation` | asset → endpoint → authorization_analysis | objective-driven access |
| `vulnerability_discovery` | technology → vulnerability_scanning → dependency_check | broad discovery |

## 1. Discovery chain — behavioral difference (not cosmetic)

`AdaptiveMissionPlanningEngine.create_mission(objective=...)` builds a distinct
per-objective capability chain. Verified:

- `bug_bounty_assessment` chain contains `vulnerability_scanning`;
  `red_team_simulation` chain contains `authorization_analysis` and no
  `vulnerability_scanning`.
- `pentest_assessment` and `vulnerability_discovery` chains differ from each
  other and from the above.

## 2. Persisted decisions differ by profile

Running each objective through the real mission runner produces distinct
decision records (`MissionDecision` persisted on the mission):

- first decision capability differs across the four profiles;
- `red_team_simulation` decisions reach `authorization_analysis`;
- `bug_bounty_assessment` decisions reach `vulnerability_scanning`.

## 3. Hypothesis generation follows profile strategy

Both profiles consume the same vulnerability engine; the evidence each profile
surfaces (and thus the hypotheses it generates) differs because the strategy
selects different capabilities at different times. `vulnerability_discovery`
reaches the vulnerability candidates and generates class-specific hypotheses
with provenance.

## 4. Continuation / stopping

All security-assessment objectives use the same vulnerability engine and
stop-condition policy: coverage cannot terminate a mission while a high-value
hypothesis is unresolved (verified in `TestHNoDumpOnlyBehavior` and
`TestNoPrematureStopOnChaining`).

## Verification

`tests/integration/test_profile_end_to_end.py` — 3 tests (distinct chains,
distinct persisted decisions, hypothesis generation per profile strategy).
`tests/integration/test_vulnerability_chaining.py::TestProfileIntegration`
confirms `bug_bounty_assessment`, `pentest_assessment`, `vulnerability_discovery`
consume the same engine; `red_team_simulation` intentionally targets
authorization instead.
