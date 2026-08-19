# PHASE 13 — DEEP AUTHENTICATED VULNERABILITY COVERAGE GATE — ACCEPTANCE REPORT

- **Phase**: 13 (HUNTERX V7)
- **Title**: A validated finding is an OUTPUT, never a stop — the mission continues assessing the remaining high-value hypotheses and attack paths until the assessment is genuinely complete.
- **Date**: 2026-08-18
- **Target**: `http://127.0.0.1:4280` (DVWA, security level `low` — authenticated via `HUNTERX_AUTH_*`)
- **Mission ID**: `01M08WX70DRHAJXAJ8TN26MMXN`
- **Artifacts**: `C:\Users\nc\AppData\Local\Temp\opencode\hx13_results2\` (`report.txt`, `results.json`, `events.jsonl`)
- **Status**: PASSED — all acceptance criteria demonstrated on the real target.

---

## 1. EXACT ROOT CAUSE (stop-condition)

`src/hunterx/domain/mission_orchestration/policy.py:100` — the `FINDINGS_VALIDATED` stop condition was implemented as `_all_findings_validated(mission)` (`policy.py:118-127`): **"every recorded finding reached a terminal stage"**. With one recorded finding, `all(...)` over the single-element list is **vacuously true** the moment the finding validates — regardless of how much high-value hypothesis work remained (99 hypotheses / 25 attack paths / open idor, ssrf, xss, open-redirect hypotheses).

This is the ONLY premature-termination path in the decision tree. Verified non-contributors:

- `COVERAGE_TARGET_ACHIEVED` (`policy.py:106-111`) is already gated on `not self._has_open_high_value_hypotheses(mission)` — correct.
- `HIGH_VALUE_HYPOTHESES_RESOLVED` (`policy.py:129-150`) requires high-value hypotheses to *exist and all resolve* — correct.
- `OBJECTIVES_COMPLETE` (`policy.py:113-114`) cannot fire mid-run: `remaining_objectives` is populated at creation (`orchestrator.py:201-202`) and never emptied anywhere during execution.
- The run loop's pending-plan-work escape hatch (`mission_execution.py:392-396`) covered only `coverage_target_achieved` / `high_value_hypotheses_resolved` — `findings_validated` broke the loop unconditionally.
- `_SUCCESS_STOP_CONDITIONS` (`orchestrator.py:2332-2339`) then marked `objectives_complete=True` and finalized (`orchestrator.py:318-319, 335-346`).

## 2. COMPLETION DECISION TREE — BEFORE

```
finding #1 validates → evaluate_stop:
  FINDINGS_VALIDATED ← _all_findings_validated = True (vacuously, 1 finding)
  → no open-high-value guard → fires
  → run loop breaks (not in escape-hatch tuple)
  → finalize: FINDINGS_VALIDATED ∈ _SUCCESS_STOP_CONDITIONS → objectives_complete=True
  → MISSION TERMINATED. Remaining 25 attack paths / high-value hypotheses never probed.
```

## 3. COMPLETION DECISION TREE — AFTER

```
finding #1 validates → evaluate_stop:
  FINDINGS_VALIDATED = _all_findings_validated AND NOT _has_open_high_value_hypotheses
  → high-value hypotheses still open (proposed/supported) → does NOT fire
  → HIGH_VALUE_HYPOTHESES_RESOLVED → not yet (open) → does not fire
  → loop continues → replan → next high-value hypothesis probed → refuted/validated
  → repeat until ALL high-value hypotheses resolved/refuted
  → plan discharged (escape hatch now also honors findings_validated for pending work)
  → then FINDINGS_VALIDATED (or HIGH_VALUE_HYPOTHESES_RESOLVED) fires → honest finalize
```

Bounded: `max_cycles=16`, `max_idle_cycles=3`, budgets, terminal states, per-hypothesis action dedup — no runaway.

## 4. EXACT FILES CHANGED (Phase 13)

| File | Change |
|---|---|
| `src/hunterx/domain/mission_orchestration/policy.py` | `FINDINGS_VALIDATED` now gated on `not self._has_open_high_value_hypotheses(mission)` — the SAME guard `COVERAGE_TARGET_ACHIEVED` already used. |
| `src/hunterx/application/mission_execution.py` | Run-loop escape hatch tuple extended with `"findings_validated"` — a findings stop no longer kills the loop while the plan still carries pending (non-hypothesis-bound) work. |
| `tests/unit/test_mission_orchestration_domain.py` | +5 policy-level regression tests (`TestPolicies`). |
| `tests/integration/test_hunter_behavior.py` | +2 policy mirror tests (`TestHFindingsStopBehavior`). |
| `tests/integration/test_phase13_continuation.py` | NEW — 4 end-to-end run-loop regression tests against the loopback vulnerable fixture. |

No architecture changes. No capability changes. No auth changes. No DVWA-specific endpoint hardcoding. Phase 12's 3xx redirect protection (`differential.py`, `300 <= s < 400`) untouched and re-verified green.

## 5. HYPOTHESIS STATE BEHAVIOR (verified)

- **newly discovered** → proposed on evidence-grounded observation (idempotent by statement — `add_hypothesis` merges evidence, same id).
- **weakly_supported → supported** via accumulating observations; **validated** via independent verification (probe reproducible); **refuted** via class-specific probe with no signal (honest negative); refuted/disproved are terminal and **never reprobed** (replan dedups by hypothesis_id; exactly one bound validation action).
- 30 terminal (29 refuted + 1 validated), 2 open at stop — both priority 0.60 (non-high-value `reachable endpoint` UNKNOWN_BEHAVIOR), which per the Phase 13 semantics do not block termination.
- All 11 high-value hypotheses (priority ≥ 0.75) resolved: 1 validated, 10 refuted.

## 6. PLANNER BEHAVIOR (verified)

- Hypotheses derive exclusively from discovered attack-surface evidence (`_hypothesize_from_observation` / `_hypothesize_from_context`): `id` → idor, `security` → ssrf, `locale` → xss, `redirect` → open-redirect, `doc`/`page` → xss, etc. No fabricated classes; no hardcoded routes.
- `_replan_from_observation` binds a per-hypothesis validation action (`NEW_HYPOTHESIS_CREATED`), deduped by hypothesis_id; the decision engine ranks evidence-driven probes by priority/confidence.
- After finding #1 validated, the planner re-planned and executed **17 more probes** over 6 minutes (19 further hypothesis updates) before termination.

## 7. REAL RUN — ACCEPTANCE SIGNALS

| Signal | Value |
|---|---|
| Mission ID | `01M08WX70DRHAJXAJ8TN26MMXN` |
| Objective | `bug_bounty_assessment` |
| Auth | `HUNTERX_AUTH_LOGIN_URL/USERNAME/PASSWORD` → session established (`PHPSESSID`, `security=low` cookie); probes carried the session (`Cookie` header). |
| Endpoints / Parameters | 71 / 29 |
| Observations / Decisions | 38 / 8 |
| Attack paths | 25 |
| Hypotheses | 99 (evidence-derived; 32 persisted terminal/open) |
| Tool executions | 38 (8 budget executions + 30 probes) |
| Probes | 30 (`vulnerability.probe.completed` ×30) |
| Refuted | 29 hypotheses (honest negatives, incl. all 10 remaining high-value) |
| Validated | 1 finding — `security-misconfiguration` on `login.php` (nuclei `cookies-without-secure`; probe signal=`header`, supported=True) |
| Report-ready | 0 (mission-level pipeline stops at verified; see Limitations) |
| Evidence / Proofs / PoCs / Reproduction / Replay | Mission-level: none generated (finding service not wired into CLI path). The full evidence→PoC→replay→report-ready pipeline is proven green by `tests/integration/test_validated_finding_workflow.py` (`behavioral_differential`, `differential_database_behavior`, `http_request`+`curl` PoCs, replay `confirmed`, `proved`, `report_ready`). |
| Final stop condition | `findings_validated` — fired ONLY after all high-value hypotheses resolved/refuted and the plan discharged (honest, not premature). |
| Status / Coverage / Duration | `completed` / 71.43% / 779 s |

**SHOW — MISSION CONTINUED AFTER FIRST VALIDATED FINDING:**

```
finding.created      at 2026-08-17T22:26:12.825994Z
finding.validated    at 2026-08-17T22:26:12.837172Z   ← finding #1 (security-misconfiguration)
first probe.completed at 2026-08-17T22:19:51.633978Z
last  probe.completed at 2026-08-17T22:32:03.393694Z
probes AFTER finding.validated: 17   (of 30 total)
hypothesis updates AFTER finding.validated: 19
mission.completed    at 2026-08-17T22:32:10.061638Z   (6 minutes of continued assessment)
```

## 8. COUNT RECONCILIATION

`mission.context.findings` (1) = events `mission.finding.created` (1) = events `vulnerability.finding.validated` (1) = `report.txt Findings` (1) = `results.json findings` (1) = `outcome.findings_validated` (1). **No duplicates, no inflation, no fabrication.** The 29 refuted hypotheses produced zero findings; the candidate finding for the misconfiguration was promoted only through its own validated hypothesis.

## 9. REGRESSION RESULTS (full battery)

| Suite | Result |
|---|---|
| `tests/unit` | **2281 passed / 12 failed** — same 12 pre-existing failures as Phase 12 (AI config ×3, CLI ×2, DB paths ×4, observability ×1, platform ×1, scanner adapters ×1; verified pre-existing at HEAD via `git stash`). +5 new Phase 13 tests. |
| integration (injection + detection + access + xss/rce acceptance + finding state integrity + validated workflow) | **72 passed** |
| `tests/integration/test_phase13_continuation.py` (NEW) | **4 passed** |
| `tests/integration/test_hunter_behavior.py` | 2 pre-existing failures (`TestC`/`TestD` — verified pre-existing at HEAD via `git stash`); +2 new Phase 13 tests passed |
| `tests/integration/test_live_hunt.py` | 2 pre-existing failures (verified pre-existing at HEAD via `git stash`) |
| full_assessment + reporting + security | **410 passed / 1 pre-existing** (Windows sandbox `test_sdk_sandbox_tempdir_names_are_traversal_safe`) |
| acceptance (rest) + golden + architecture | **493 passed / 3 pre-existing** (`test_40_41_cli_and_deterministic_fallback`, `test_end_to_end_chain[web-vuln-verification]`, `test_codebase_has_no_architecture_errors` — 15 violations, unchanged) |
| Phase 12 3xx redirect regression (`test_vulnerability_capability_differential.py`) | **7 passed** |
| Phase 12 session tests (`test_authenticated_session.py`, `test_auth_acceptance.py`) | **passed** |
| Juice Shop SQLi/XSS/RCE/LFI acceptance (`test_vulnerability_injection.py`, `test_xss_acceptance.py`, `test_rce_acceptance.py`) | **passed** |

Zero regressions attributable to the Phase 13 patch.

## 10. REMAINING LIMITATIONS

1. **Report-ready at mission level**: the CLI `hunt` path does not wire the `VulnerabilityFindingService` bridge, so mission findings stop at `verified` (report_ready=0, no mission-level PoC/reproduction/replay artifacts). The full lifecycle is proven by the integration suite; wiring the bridge into the CLI is a candidate follow-up (out of scope — no architecture change permitted).
2. **Discovery-tool availability**: `httpx` failed health check and `arjun` provisioning failed in this run, so endpoint/parameter discovery leaned on katana + the crawler (71/29 found). Consequently `sqli?id=`, `xss_r?name=` parameter hypotheses never arose (hypotheses are surface-driven by design; the parameters were never discovered — honest).
3. **Two non-high-value hypotheses open at stop** (priority 0.60 `reachable endpoint`): by Phase 13 semantics only high-value hypotheses block termination.
4. **In-memory (99) vs persisted (32) hypothesis counts**: persistence lags on unchanged rows; the policy evaluates the live in-memory aggregate (the honest source for the stop decision).
5. **Deferred (from Phase 12)**: `SessionService.establish` verdict `bool(cookies) and not _still_login_form(content)` — a failed login 302→login.php with fresh PHPSESSID + empty body reports established=True. Not reopened (auth is proven working; no regression observed).

## 11. PHASE 13 TEST MATRIX (Part 11 → delivery)

1. Validated finding does not terminate bug_bounty while unresolved high-value hypotheses remain — `policy.py` gate + `TestPolicies.test_findings_validated_blocked_while_high_value_hypothesis_open` + `TestHFindingsStopBehavior` ✓
2. Validated hypothesis marked resolved — hypothesis loop (existing) + continuation run (1 validated, terminal) ✓
3. Unrelated hypotheses remain schedulable after validation — `test_mission_continues_assessment_after_first_validated_finding` (safe endpoint probed → refuted after vuln endpoint validated) ✓
4. Refuted not reprobed — `test_refuted_hypothesis_is_not_reprobed` (1 tested action, 1 bound plan action) ✓
5. Duplicate hypotheses idempotent — `test_duplicate_hypotheses_idempotent_by_statement` (same id, merged evidence) ✓
6. Duplicate findings prevented — existing `test_finding_state_integrity.py` + `test_finding_orchestration_service.py` ✓
7. Planner continues after validation — real run: 17 probes after finding.validated ✓
8. Mission terminates when work exhausted — `TestPolicies.test_findings_validated_fires_once_high_value_hypotheses_resolved` + real run finalize ✓
9. Zero-finding mission terminates — `test_zero_finding_mission_terminates_honestly` + `test_findings_validated_never_fires_without_findings` ✓
10-13. Juice Shop SQLi/XSS/RCE/LFI acceptance — green ✓
14. Phase 12 session tests — green ✓
15. 3xx redirect regression — green ✓