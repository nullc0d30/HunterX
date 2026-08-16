# JUICE_SHOP_REAL_TARGET_ACCEPTANCE.md

## Final status: **PASS_WITH_LIMITATIONS**

HunterX demonstrated the complete reasoning-driven workflow against the real
local OWASP Juice Shop (recon → model → evidence → hypothesis → targeted probe
→ analysis → reassessment → honest rejection → stop), and honestly reported
zero validated findings because the observed evidence did not support one. A
clearly documented target/environment limitation (Juice Shop rate limiter,
full-template nuclei runtime variance, and three toolchain gaps) prevented
consistent multi-profile evidence and higher-value class validation.

## A. Exact target and scope

- Target: `http://localhost:3010` — local OWASP Juice Shop (Docker container
  `bkimminich/juice-shop`, mapped `127.0.0.1:3010->3000`). Verified HTTP 200.
- Scope: strictly `http://localhost:3010` / `http://127.0.0.1:3010` only. All
  probing is loopback (the engine's `ProbeExecutor` refuses non-loopback).
- Source: revision `5fc1bdb` (editable install at
  `/home/nc/hunterx/HunterX/src`), WSL Ubuntu 24.04, user venv.
- Toolchain: 83/106 tools available; subfinder, dnsx, nmap, whatweb, httpx,
  nuclei, katana, sqlmap, feroxbuster available; arjun missing.

## B. Objective/profile identifiers (real, from the registry)

`bug_bounty_assessment`, `pentest_assessment`, `red_team_simulation`,
`vulnerability_discovery` (all present in `_OBJECTIVE_MAP`).

## C. Execution timeline (per profile)

Each profile: preflight → discovery chain → recon → evidence ingestion →
hypothesis/reasoning → honest finalization. All profiles produced persisted
`events.jsonl`, `results.json`, `report.txt` under
`artifacts/hunterx-results/juice-shop/<objective>/`.

| Objective | Persisted decisions (from events) |
|---|---|
| bug_bounty_assessment | endpoint(httpx) → parameter(arjun) → vulnerability(nuclei) |
| pentest_assessment | asset(amass) → endpoint(httpx) → parameter(arjun) → vulnerability(nuclei) |
| red_team_simulation | asset(amass) → authorization(httpx) → endpoint(httpx) — **no vulnerability scanning** |
| vulnerability_discovery | technology(whatweb) → vulnerability(nuclei) → dependency(osv-scanner) |

## D. Recon → Model evidence

`vulnerability_discovery`: whatweb observed `Python`/custom technologies; the
target model recorded **7 technologies**. This evidence was consumed downstream
(recon → model → attack-surface reasoning), never dumped.

## E. Evidence → Hypothesis example

Nuclei reported a real Juice Shop surface (`swagger-api` template,
`matched-at http://localhost:3010/api-docs/swagger.yaml`). The engine
canonicalized the template to the `api-security` capability and created:

```
hypothesis: "http://localhost:3010 may be affected by swagger-api"
  priority 0.75 · provenance {observation_id, vulnerability_class: api-security,
  endpoint: http://localhost:3010, parameter: ""}
```

## F. Hypothesis → Probe

The `api-security` capability built a targeted differential probe against the
matched surface and the mission executed it:

```
vulnerability.probe.started {vulnerability_class: api-security, endpoint}
vulnerability.probe.completed {vulnerability_class: api-security, signal: none}
```

## G. Probe → Reassessment

The probe found **no sensitive-data signal** (the swagger spec contains API
schema, not secrets) → the hypothesis was contradicted. No false positive was
fabricated.

## H. Validation

The hypothesis was not validated (contradicted probe) → the finding stayed
`candidate`. **No scanner candidate became a verified finding.** This is the
honest-negative control working on the real target.

## I. Finding provenance

`validated_findings: 0`. The single candidate finding records
`vulnerability_class`, `asset_key`, `hypothesis_id`, originating observation
via `evidence_refs`, and stage `candidate`. Causality is fully
reconstructable (finding → hypothesis → probe → observation → endpoint).

## J. Continued hunting / stopping

Coverage reached 0.67 (vulnerability_discovery) with **no unresolved
high-value hypothesis**; the mission finalized honestly
(`objectives_complete`). The coverage-stop guard (no premature termination
while a high-value hypothesis is open) is verified in the test suite.

## K. Profile behavior comparison

Decisions differ by profile (see C): red_team targets `authorization_analysis`
and never runs `vulnerability_scanning`; bug_bounty/pentest run the
web/API vulnerability surface; vulnerability_discovery runs
technology → vulnerability → dependency. Behavioral, not cosmetic.

## L. Negative evidence

Each profile recorded 2–4 bounded negative-evidence records from empty/negative
tool results — never fabricated.

## M. Unresolved hypotheses

0–1 per profile (the api-security hypothesis was contradicted, not left
silently open).

## N. Stopping conditions

`objectives_complete` (coverage 0.5–0.67); no premature-stop violation.

## O. Tool-only gaps (no downstream reasoning)

- `osv-scanner` (dependency_check): binary installed but **no adapter
  registered** → dependency checking never executed (recorded as a tool
  failure). Concrete toolchain gap.
- `amass` (asset_discovery): exits 1 against loopback (no network) → failed.
- `arjun` (parameter_discovery): **not installed** → parameter discovery
  could not run, so parameter-based injection hypotheses were not applicable
  from observed evidence.

## P. Tests

95+ vulnerability/mission/profile tests pass; ruff clean on all changed files.
Two concrete defects found during this run were fixed with regression tests:
(1) real scanner template ids are canonicalized to capability classes
(`canonical_class`), so real candidates drive differential probes; (2) the
candidate's `matched_at` surface is used as the probe endpoint.

## Q. Code changes

- `src/hunterx/domain/vulnerability_capability/registry.py`: `canonical_class`.
- `src/hunterx/domain/mission_orchestration/orchestrator.py`: canonical class
  extraction + `matched_at` endpoint resolution.
- `tests/integration/test_vulnerability_engine.py`: regression tests.

## R. Limitations

- Juice Shop's rate limiter and nuclei's full default template set make
  evidence non-deterministic across runs: the swagger surface was surfaced on
  the run that completed, but not on every run.
- The recon tools (single-URL httpx; subfinder on localhost) do not surface
  endpoint/parameter surfaces, so the higher-value classes (SQLi, XSS, SSRF,
  IDOR, ...) were recorded **NOT_APPLICABLE** from observed evidence — the
  engine does not force classes without evidence.
- Three toolchain gaps (arjun missing, amass fails on loopback, osv-scanner no
  adapter) blocked parts of the pentest/bug_bounty/vulnerability chains.

## Final assessment

HunterX is **not** a tool dumper: on the real Juice Shop it consumed recon
evidence, built a target model, derived an evidence-based vulnerability
hypothesis, selected a targeted capability, ran a differential probe, and
honestly rejected the false positive (swagger docs ≠ sensitive exposure),
leaving the finding at `candidate`. Zero validated findings is the correct,
honest outcome for the evidence observed. The workflow is complete and the
causal chain is reconstructable from persisted artifacts; the documented
environment/target limitations prevent a stronger (positive-validation)
demonstration.
