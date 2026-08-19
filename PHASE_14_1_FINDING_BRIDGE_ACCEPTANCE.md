# Phase 14.1 — Finding Bridge Acceptance

**Status: PASSED** · Real CLI hunt against DVWA (127.0.0.1:4280) produced 2 REPORT_READY findings through the complete finding-orchestration lifecycle.

## 1. Scope

Phase 14.1 (HUNTERX V7, strict mode): the real CLI hunt path
`hunterx hunt bug_bounty_assessment <target>` must automatically bridge a
validated mission finding into `VulnerabilityFindingService` and complete the
existing lifecycle — evidence → reproduction → PoC → replay → impact →
confidence → REPORT_READY — without seeding, hardcoding or fabricating.

**Root cause (Phase 13 gap).** The bridge code and the platform wiring already
existed: `platform/assembler.py` wires `vulnerability_finding_service` into
`MissionExecutionService` (`finding_service=...`), and
`mission_execution._materialize_validated_finding` calls
`service.create_finding` + `service.complete_validated_finding`. The Phase 13
real run created exactly one `FindingRecord` — but with class coerced to
`unknown_behavior`, because `FindingVulnerabilityClass` had no
`security_misconfiguration` member. `verify_with_probe` then resolved
`unknown-behavior` to no registered capability → `blocked: no targeted probe
available` → the finding stayed CANDIDATE forever → report_ready = 0.

**Fix.** Completed the finding-domain vocabulary for the capability that is
already registered and was already probed in real runs
(`SecurityMisconfigurationCapability`, registry class
`security-misconfiguration`):
- `domain/vulnerability_finding/enums.py`: added
  `SECURITY_MISCONFIGURATION = "security_misconfiguration"` to
  `FindingVulnerabilityClass` and `ValidationStrategyFamily`.
- `domain/vulnerability_finding/evidence.py`: hypothesis
  (`detection_signature`, `header`), validation
  (`behavioral_differential`, `independent_reproduction`) and proof
  (`controlled_proof`, `replay`) kinds for the class.
- `domain/vulnerability_finding/strategy.py`: family tool candidates
  (`nuclei`), capability (`vulnerability_scanning`) and read-only
  safe-validation policy for the family.
- `application/mission_execution.py`: idempotency guard in
  `_materialize_validated_finding` — a hypothesis provenance
  (`hypothesis:<id>`) never creates a duplicate `FindingRecord`, and an
  already-REPORT_READY record is not re-completed.

No new probe logic, no new differential, no new capability, no auth change, no
completion-policy change, no HTTP 402/404/502 bypass, no architecture
refactor. Impact assessment was already evidence-driven
(`BEHAVIORAL_DIFFERENTIAL` → confidentiality/integrity) and required no change.

## 2. Real acceptance run

- Command (WSL python, env-only auth): `hunterx hunt --json --output hx14_results bug_bounty_assessment http://127.0.0.1:4280`
- Auth: `HUNTERX_AUTH_LOGIN_URL=http://127.0.0.1:4280/login.php`,
  `HUNTERX_AUTH_USERNAME=admin`, `HUNTERX_AUTH_PASSWORD=password`
  (env-only; **zero occurrences** of the password in report.txt / results.json).
- Mission: `01M09H57WVHFET5YMEARSSFYHQ` · objective `bug_bounty_assessment`
  · preflight passed · status `completed` · stop condition `findings_validated`
  · 1145 s · 8 executions · 25 attack paths · coverage 0.6667.
- Surface: 53 endpoints, 10 parameters, 19 observations, 64 hypotheses
  (20 open at stop), 11 hypotheses resolved.
- Artifacts: `hx14_results/report.txt`, `hx14_results/results.json`,
  `hx14_results/events.jsonl`; DB `hx14.db`.

## 3. Findings

| # | Class | Endpoint | Severity | Source | Result |
|---|-------|----------|----------|--------|--------|
| 1 | security-misconfiguration | http://127.0.0.1:4280 | info | nuclei candidate → differential probe (signal=header, supported) | REPORT_READY |
| 2 | xss | http://127.0.0.1:4280/vulnerabilities/view_help.php?id=javascript&locale=en&security=low | high | differential probe on `locale` (supported) | REPORT_READY |

Both traverse: discovery → hypothesis → targeted probe → validation →
`FindingRecord` (provenance `hypothesis:<id>`) → verification re-probe →
`behavioral_differential` evidence → reproduction → PoC (http_request
proof-validated + curl static-validated) → real replay (verdict `confirmed`)
→ impact (confidentiality high, integrity high) → confidence (0.838, high) →
REPORT_READY.

Lifecycle transitions (both findings): candidate → supported →
validation_required → validating → validated → proof_required → proving →
proved → report_ready. A `validated → proof_required` transition was
**denied** once (missing validation sufficiency) before the evidence allowed
it — proof that REPORT_READY stays checklist-gated.

Report checklist: 14/14 checks passed for both findings (title, asset,
location, description, impact, severity, evidence, reproduction, proof,
validation_status, confidence, scope, redaction, provenance).

Mission-context findings reflect `stage=report_ready` (report.txt line 251-252)
and the reporting path consumes REPORT_READY:
report.txt "Validated findings 2 · Report-ready findings 2"; results.json
`findings=2, validated_findings=2, report_ready_findings=2`.

## 4. Honesty checks

- No seeding/hardcoding: both findings derive from genuine probe verdicts
  (signal header / supported xss differential) with real re-execution.
- Contradicted probes never validate: `/safe/headers` and `/safe/search`
  surfaces produced no FindingRecord (integration + service tests).
- Duplicate protection: exactly one FindingRecord per hypothesis provenance;
  re-invoking materialization is a no-op (verified by test + DB).
- REPORT_READY gated: no evidence → not reportable; safe surface → not
  reportable; denied transition observed in the real run.
- Auth secrets masked in all artifacts.

## 5. Regression results (Phase 5/12/13 unchanged)

| Suite | Result |
|-------|--------|
| unit | 2281 passed / 12 failed — identical pre-existing 12 (ai_config, cli, db_paths, observability catalog, platform, scanner_ids; Windows sandbox env) |
| integration core (injection/detection/access/xss/rce/finding state/validated workflow/phase13) | 97 passed |
| tests/integration/test_phase14_1_finding_bridge.py (NEW) | 9 passed |
| full_assessment + reporting golden | 45 passed, 7 skipped |
| integration security/reporting/full-assessment subset | 15 passed |
| acceptance + architecture | 340 passed / 3 failed — pre-existing (cli.commands→tools.readiness layer violations, toolchain env, CLI sandbox) |
| golden (rest) | 115 passed |
| test_hunter_behavior | 12 passed / 2 failed — pre-existing (TestC, TestD) |
| test_live_hunt | 2 failed — pre-existing (TestLiveHuntCLI) |

Zero regressions; every failure matches the Phase 13 baseline.

## 6. Files changed

- `src/hunterx/domain/vulnerability_finding/enums.py`
- `src/hunterx/domain/vulnerability_finding/evidence.py`
- `src/hunterx/domain/vulnerability_finding/strategy.py`
- `src/hunterx/application/mission_execution.py` (idempotency guard)
- `tests/integration/test_phase14_1_finding_bridge.py` (new, 9 tests)

## 7. Remaining limitations

- `events.jsonl` (MissionRunRecorder) subscribes only to `mission.*`,
  `vulnerability.*`, `tool.command`, `coverage.updated` — `finding.*`
  lifecycle events are not mirrored; the DB is authoritative (pre-existing
  recorder filter, not changed).
- DVWA low yields security-misconfiguration as the dominant validated class;
  other classes (lfi/sqli on real DVWA endpoints) are not reached because
  their parameters are not discovered from crawled links.
- Coverage 0.6667 with 20 open hypotheses at stop (findings_validated policy —
  unchanged by this phase).
- The class `security-misconfiguration` severity comes from the candidate
  (info); impact assessment raises confidentiality/integrity to high from
  evidence.