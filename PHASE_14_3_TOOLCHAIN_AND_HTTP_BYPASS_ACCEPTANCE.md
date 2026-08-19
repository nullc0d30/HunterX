# Phase 14.3 — Toolchain Health + HTTP Status/Access-Control Bypass

**Status: COMPLETE**

## 1. Toolchain audit

Audited catalog / installer / provisioning / PATH / readiness / adapter / argv /
invocation / parser / observation / planner integration for httpx, arjun, katana,
nuclei, ffuf, sqlmap.

| Tool | Version | Path | Readiness | Real invocation (adapter argv) |
|------|---------|------|-----------|-------------------------------|
| httpx | 1.10.0 | `/opt/hunterx/tools/bin/httpx` | available | rc=0, 4 technology observations from JSONL |
| arjun | 2.2.6 | `/home/nc/.local/arjun-venv/bin/arjun` | available (INVOCATION_VERIFIABLE) | rc=0, `-o` JSON report read+parsed (params `security`,`PHPSESSID` captured) |
| katana | 1.7.0 | `/opt/hunterx/tools/bin/katana` | available | rc=0, crawled fixture index, URLs parsed |
| nuclei | 3.11.1 | `/opt/hunterx/tools/bin/nuclei` | available | rc=0 (broad scan; bounded by engine timeout) |
| ffuf | 2.1.0 | `/opt/hunterx/tools/bin/ffuf` | available | **broken invocation (see §2)** |
| sqlmap | 1.8.4 | `/usr/share/sqlmap/sqlmap.py` | available | rc=0, `--batch` bounded crawl, parsed |

The run PATH (tools/bin + arjun-venv first) resolves every tool correctly.

## 2. Exact failures (PART A)

1. **ffuf adapter emits a broken argv when `wordlist` is absent**: `build_argv`
   produced `ffuf -u <url> -w '' -o - -of json ...`; the binary rejects it
   (rc=1, `read /tmp: is a directory`). Its siblings (gobuster/feroxbuster/
   dirsearch/kiterunner) all fail closed with `raise ValueError(... 'wordlist' ...)`.
   No wordlist is provisioned on this host, so every real ffuf invocation was
   broken.
2. **httpx name shadowing (environmental)**: the Python `httpx` client
   (`/opt/hunterx/venv/bin/httpx`) shares the name with ProjectDiscovery httpx.
   On a bare venv PATH the wrong binary resolves (`-version`/`-u` rejected).
   Readiness **correctly detects this** (status `SHADOWED`); the launcher pins
   `$HUNTERX_TOOL_BIN`/tools/bin ahead of venv paths. Not a product defect — an
   environment finding; the correct binary is used on the run PATH.
3. **arjun not on the default PATH** — only in its venv; run PATH includes it.
   Readiness resolves it via `PATH`/preferred dirs.
4. **nuclei invocation is broad** (no template filter by default); bounded only by
   the engine timeout. Works; documented, not changed.

## 3. Exact fixes (PART A)

- `src/hunterx/tools/content/ffuf.py::FfufAdapter.build_argv` — **fail closed** on a
  missing/empty `wordlist` (`raise ValueError("ffuf requires a 'wordlist' parameter")`),
  matching its sibling content adapters. Never emits `-w ''`. Verified:
  fail-closed without a wordlist; correct argv with one.

## 4. Invocation verification (PART A)

Real bounded invocations through each adapter against live local targets produced
output matching the adapter contracts: httpx (4 technology observations), katana
(URLs), arjun (`-o` report read/parsed with session cookie), sqlmap (bounded
batch, parsed). Readiness `check()` reports all six `available` on the run PATH.

## 5. HTTP bypass root cause / design

The generic `http-access-differential` capability already modeled the correct
semantics (baseline restricted → controlled mutation → meaningful access proof;
status-only never a vulnerability) but was **inert** in real missions:
- **Gap A (discovery)**: per-endpoint HTTP statuses were never recorded, so the
  orchestrator's restricted-status hypothesis derivation (`401/402/403/404/405/502`)
  never fired.
- **Gap B (verification)**: `analyze` required a pre-configured `proof_marker`
  (never set in real discovery), so every probe returned uninformative.

Design: record the observed status of each endpoint the mission fetches during
parameter discovery; a restricted status derives the access-control hypothesis;
the capability then verifies meaningful access — a proof marker when configured,
or a generic fallback requiring a success response with substantive content
distinct from the restricted baseline and not a generic error/login wall.

## 6. Vulnerability class

`http-access-differential` — already registered (`is_vulnerability_class`),
finding enum `HTTP_ACCESS_DIFFERENTIAL`, hypothesis category `AUTHORIZATION_ISSUE`.
No new class added.

## 7. Capability

`HttpAccessDifferentialCapability` (`capabilities/access.py`): `can_apply` requires
endpoint + observed status; `build_probes` emits controlled mutations (trailing
slash, `/.`, POST, HEAD); `analyze` requires meaningful access. Generic fallback
added: restricted baseline (`>= 400`) → mutation returns success (`2xx`) with
substantive body (`>= 64` bytes) distinct from baseline and not a generic
denied/login body → supported; else contradicted/uninformative.

## 8. Hypothesis derivation

`_hypothesize_from_context` derives the hypothesis for any endpoint recorded with
status 401/402/403/404/405/502. `_form_field_observation` now records the observed
status for every endpoint the mission fetches during parameter discovery (generic,
any app); the hook ingests a `status_code` endpoint observation and the hypothesis
is derived on ingest.

## 9. Probe mechanism

Loopback-only (`is_loopback_target`) differential probe: baseline GET (restricted)
plus controlled mutations. Never leaves the local host; never fuzzes; never a
destructive request.

## 10. Meaningful-access verification

- Proof-marker path (unchanged, strongest): marker present in a mutated response
  and absent from the baseline.
- Generic path (new): a controlled mutation must turn a restricted response into a
  **success response carrying substantive content** (not the baseline body, not a
  generic error/login wall). `200→404`, `404→502`, `502→200` alone are never valid.

## 11. Negative controls

`/statusbypass` (403→200 "ok"), `/lengthonly` (403→200 generic denied body),
`/error` (502→503), `/safe/protected` (403→403), `/safe/hidden` (404→404) — all
REFUTED/contradicted in capability tests and in the real CLI mission probes
(signal `none`, `supported=False`).

## 12. Evidence

Verdict evidence includes baseline/mutated status, the mutation, and a bounded
response excerpt. Finding service persists `evidence_refs` (detection +
differential), reproduction records (`actual_result: "...mutation {'path':
'/hidden/'} turned a restricted response into meaningful content..."`), PoCs,
replay, impact.

## 13. Reproduction

`tidb_finding_reproductions`: request `GET <target>/hidden`, actual result is the
meaningful-access differential (baseline 404 vs mutation `/hidden/` protected
content), redacted.

## 14. PoC

`tidb_finding_pocs`: `http_request` (proof_validated) and `curl`
(static_validated), redacted, deterministic, scope-bound.

## 15. Replay

`tidb_finding_replay_records`: `scope_verified=1`, `hypothesis_verified=1`,
`evidence_class=http_access_differential`, **verdict `confirmed`**.

## 16. Validated findings

Real fixture (`AccessBypassApp`, real tools, no fakes):
`http-access-differential on <target>/hidden` (404 baseline, mutation exposes
protected content) — **validated**; `/lengthonly` and `/error` hypotheses
**refuted**. DVWA re-run: **0** http-access-differential hypotheses/findings.

## 17. REPORT_READY

`/hidden` finding: `report_ready`, severity high, confidence 0.737, report
checklist `complete=1`/`reportable=1`.

## 18. Regression results

- phase14_2 + phase14_3 + http_bypass_acceptance + phase13_continuation +
  authenticated_session + mission_orchestration_domain + attack_surface_completion
  + technology_adapters: **153 passed, 2 skipped** (real-binary tests skip on the
  Windows pytest runner; covered by the WSL acceptance run).
- toolchain_golden + vulnerability_detection + xss_acceptance +
  finding_orchestration (service/domain/engines): **79 passed**.
- mission_execution_defects: **21 passed**.
- Real DVWA assessment unchanged (LFI validated; SQLi/XSS/RCE behavior unchanged —
  see §18 note) with **no bypass false positives**.

Note: the Phase 14.3 DVWA re-run also surfaced the pre-existing engine-consistent
xss/idor detections on DVWA's by-design `view_source`/`view_help` (a Phase 14.2
auth-fix consequence on authenticated pages, present since the cookie fix); these
are unchanged by Phase 14.3 and documented in Phase 14.2.

## 19. Pre-existing failures (untouched)

`tools/test_cli.py` ×3 (SMB sqlite lock), `test_mission_preflight.py` ×4 (stub
`profile_tools=`), architecture ARCH-007/003, `xss-detection` tool-selection
acceptance failure — all documented pre-existing, not introduced or fixed here.

## 20. Limitations

- Real-mission endpoint status recording currently runs in the parameter-discovery
  (arjun) phase; endpoints not parameter-targeted within the cycle budget are not
  status-recorded. The dedicated fixture puts the bypass endpoints first so a
  bounded mission reaches them; a broader surface needs a larger cycle budget.
- Nuclei's default invocation is the full template set (bounded by the engine
  timeout); a template filter would make it bounded at the cost of coverage.
- httpx works only when `tools/bin` precedes the venv on PATH (launcher pinned);
  on a bare venv PATH the Python httpx client shadows it and readiness reports
  `SHADOWED` rather than silently failing.

## Artifacts

- Fixture acceptance: `/tmp/hx14access.db`, `/tmp/hx14p143_fixture/{report.txt,results.json,events.jsonl}`.
- DVWA regression re-run: `/tmp/hx14p143.db`.
- Tests: `tests/integration/test_phase14_3_http_bypass_and_toolchain.py`,
  `tests/framework/access_bypass_app.py`.
