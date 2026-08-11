# Full-Spectrum Security Assessment Validation Matrix (Sprint 033)

> **Status**: Ratified
> **Wave**: 18 — Full-Spectrum Security Assessment Validation
> **Engine**: `hunterx.platform.build_platform` (composition root)
> **Orchestrator**: `hunterx.engines.mission_orchestration.engine.MissionOrchestrationEngine`

Sprint 033 proves that HunterX v7 operates as an **integrated security
assessment platform** across seven mission classes — bug bounty, web pentest,
API security, external attack surface, cloud/SaaS, vulnerability research and
red-team recon. Every mission exercises the full loop:

```
DISCOVER → ENUMERATE → UNDERSTAND → MAP → HYPOTHESIZE → TEST → CORRELATE →
VALIDATE → PROVE → REPLAY → ASSESS IMPACT → REPORT → REASSESS
```

This matrix records the capability, the integrated tools, the input/output
contracts, the parser/normalizer/evidence mapping, the correlation, validation,
proof, persistence, the test coverage and the current status of every
validated capability.

---

## 1. Capability matrix

Legend — Status: `✅ VALIDATED` (green test), `🧪 PARTIAL` (needs an installed
binary or external service), `📋 CONTRACTED` (declared contract, offline
replay).

| Capability | Tools | Input | Output | Parser | Normalizer | Evidence | Correlation | Validation | Proof | Persistence | Tests | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Subdomain discovery | Amass, Subfinder, Assetfinder, Findomain, Shuffledns, MassDNS | domain | subdomains (JSON/JSONL) | `recon-json`, `recon-text` | `recon-normalizer` | `CanonicalObservation(domain)` | cross-tool dedupe by `sub:<name>` | mission hypothesis → coverage | proof cell `subdomain_enumeration` | `IntelligenceAssetRecord`, `ObservationRecord` | `tests/acceptance/full_assessment/test_bug_bounty_mission.py`, `test_red_team_recon_mission.py` | ✅ VALIDATED |
| DNS enumeration | DNSx, MassDNS | domain/host | DNS records | `dns-json`, `dnsx-jsonl` | `dns-normalizer` | `CanonicalObservation(dns_record)` | resolves host → IP | coverage `dns_enumeration` | — | `DnsService` records | `test_attack_surface_mission.py`, `test_red_team_recon_mission.py` | ✅ VALIDATED |
| Port / service discovery | Naabu, Nmap, Masscan, RustScan | IP/host | open ports + services | `live-observations`, `nmap-xml`, `naabu-jsonl`, `masscan-json` | `live-normalizer` | `CanonicalObservation(port/service)` | Nmap+Naabu+Masscan unified service inventory; conflict preserved | coverage `port_discovery`/`service_detection` | — | `LiveHostService` records, `IntelligenceAssetRecord` | `test_attack_surface_mission.py`, `test_red_team_recon_mission.py` | ✅ VALIDATED |
| HTTP probing | HTTPx | host/URL | status/headers/title | `technology-observations` | `technology-normalizer` | `CanonicalObservation(service)` | HTTPx+WhatWeb+Nuclei unified web intel | coverage `service_detection` | — | `TechnologyObservationRecord` | all mission tests | ✅ VALIDATED |
| Technology fingerprinting | WhatWeb, HTTPx | URL | technology stack | `technology-observations` | `technology-normalizer` | `CanonicalObservation(technology)` | cross-tool dedupe | coverage `technology_fingerprint` | — | `TechnologyObservationRecord` | `test_bug_bounty_mission.py`, `test_web_pentest_mission.py` | ✅ VALIDATED |
| URL discovery | Katana, Gospider, Hakrawler, GAU, Waybackurls | URL/domain | URL inventory | `web-observations` | `web-normalizer` | `CanonicalObservation(url)` | Katana+GAU+Waybackurls+Gospider unified URL inventory | coverage `endpoint_enumeration` | — | `WebOriginRecord`, `URLObservationRecord` | `test_bug_bounty_mission.py`, `test_api_security_mission.py` | ✅ VALIDATED |
| Content discovery | FFUF, Feroxbuster, Gobuster, Dirsearch | URL | paths/files | `ffuf-json` | `content-normalizer` | `CanonicalObservation(url)` | dedupe by URL | coverage `content_discovery`; decoy rejected as negative | — | `URLObservationRecord` | `test_vulnerability_research_mission.py` | ✅ VALIDATED |
| Parameter discovery | Arjun, ParamSpider, Kiterunner | URL | parameters | `parameter` normalizer | `web-normalizer` | `CanonicalObservation(parameter)` | Arjun+ParamSpider+Kiterunner unified param inventory | coverage `parameter_discovery` | — | `parameters` context + records | `test_bug_bounty_mission.py`, `test_api_security_mission.py` | ✅ VALIDATED |
| JavaScript analysis | LinkFinder, SecretFinder, xnLinkFinder | URL/JS | routes + secrets | `javascript-analyses` | `javascript-normalizer` | `CanonicalObservation(javascript/secret)` | JS routes → endpoint inventory; secret → credential hypothesis | coverage `javascript_analysis`/`secret_detection` | proof cell `secret_detection` | `JavaScriptService` records | `test_bug_bounty_mission.py`, `test_red_team_recon_mission.py` | ✅ VALIDATED |
| API mapping | HTTPx, Katana, Kiterunner, ZAP, mitmproxy | URL | endpoints/methods/params/schemas | `web-observations`, `api` normalizer | `api-normalizer` | `CanonicalObservation(api)` | Kiterunner+Arjun+Katana+HTTPx unified API inventory | coverage `api_mapping` | — | `WebAPIEndpointRecord` | `test_api_security_mission.py`, `test_red_team_recon_mission.py` | ✅ VALIDATED |
| GraphQL enumeration | InQL, GraphQLmap | GraphQL endpoint | schema/ops/introspection | `graphql` normalizer | `api-normalizer` | `CanonicalObservation(graphql)` | InQL+GraphQLmap corroboration | coverage `graphql_enumeration`/`graphql_security` | proof cell `graphql_security` | `WebGraphQLEndpointRecord` | `test_api_security_mission.py` | ✅ VALIDATED |
| Vulnerability scanning | Nuclei | URL/endpoint | template matches | `nuclei-jsonl` | `vulnerability-candidate-normalizer` | `CanonicalObservation(vulnerability)` | Nuclei + manual differential + SQLmap/Ghauri consensus | candidate → hypothesis → validated | proof via `sqlmap`/`proof-replay` | `FindingRecord` | all mission tests | ✅ VALIDATED |
| SQL injection | SQLmap, Ghauri | endpoint + param | confirmed injection | `sqlmap` adapter parse | `vulnerability-candidate-normalizer` | differential error behavior | Nuclei + differential + SQLmap consensus | validated hypothesis → proven finding | `proof-replay`, proof cell | `FindingRecord`, `ReplayRecord` | `test_bug_bounty_mission.py`, `test_vulnerability_research_mission.py` | ✅ VALIDATED |
| XSS | Dalfox, XSStrike | endpoint + param | reflected/stored XSS | `xss` normalizer | `vulnerability-candidate-normalizer` | reflection evidence | contradictory tools preserved; inert reflection → negative | false positive rejected | — | `NegativeResultRecord` | `test_bug_bounty_mission.py`, `test_vulnerability_research_mission.py` | ✅ VALIDATED |
| SSRF | Interactsh, nuclei | endpoint + param | OOB callback | `ssrf` normalizer | `vulnerability-candidate-normalizer` | callback evidence | SSRF → internal service discovery cascade | validated hypothesis → proven finding | proof cell `ssrf` | `FindingRecord`, `Interactsh` callback | `test_vulnerability_research_mission.py` | ✅ VALIDATED |
| SSTI | SSTImap, Tplmap | endpoint + param | template engine evaluation | `ssti` normalizer | `vulnerability-candidate-normalizer` | rendered payload evidence | SSTI class tested | validated hypothesis → proven finding | proof cell `ssti` | `FindingRecord` | `test_vulnerability_research_mission.py` | ✅ VALIDATED |
| LFI / path traversal | nuclei, manual | endpoint + param | file read | `lfi` normalizer | `vulnerability-candidate-normalizer` | response body evidence | LFI class tested | validated hypothesis | — | `FindingRecord` | golden dataset coverage | 🧪 PARTIAL |
| Command injection | Commix | endpoint + param | command execution | `rce` normalizer | `vulnerability-candidate-normalizer` | time/body evidence | RCE class tested | validated hypothesis | — | `FindingRecord` | golden dataset coverage | 🧪 PARTIAL |
| XXE | XXEinjector | endpoint (XML) | entity resolution | `xxe` normalizer | `vulnerability-candidate-normalizer` | OOB/file read | XXE class tested | validated hypothesis | — | `FindingRecord` | golden dataset coverage | 🧪 PARTIAL |
| GraphQL weaknesses | GraphQLmap, InQL | GraphQL endpoint | introspection/DoS/field abuse | `graphql` normalizer | `api-normalizer` | introspection evidence | GraphQL classes tested | validated hypothesis → proven finding | proof cell `graphql_security` | `FindingRecord` | `test_api_security_mission.py` | ✅ VALIDATED |
| Authorization / BOLA | ZAP, nuclei, manual | endpoint + context | cross-object/role access | `authorization-observations` | `authorization-normalizer` | `CanonicalObservation(authorization)` | context-aware cross-role testing | validated hypothesis → proven finding | proof cell `authorization_analysis`/`api_security` | `AuthorizationService` records, `FindingRecord` | `test_web_pentest_mission.py`, `test_api_security_mission.py`, `test_red_team_recon_mission.py` | ✅ VALIDATED |
| Authentication weakness | HTTPx, mitmproxy, ZAP | auth endpoints | session/CSRF/credential issues | `auth-observations` | `auth-normalizer` | session evidence | session behavior across contexts | validated hypothesis → proven finding | proof cell `authentication_analysis` | `AuthService` records, `FindingRecord` | `test_web_pentest_mission.py` | ✅ VALIDATED |
| Secrets detection | Gitleaks, TruffleHog, SecretFinder | repo/JS/endpoint | leaked secrets | `gitleaks-json`, `javascript-analyses` | `secret-normalizer` | `CanonicalObservation(secret)` | Gitleaks+TruffleHog+SecretFinder unified secret intel; fake secrets rejected | secret → credential hypothesis | proof cell `secret_detection` | `SecretExposureRecord`, `FindingRecord` | `test_red_team_recon_mission.py`, `test_cloud_saas_mission.py` | ✅ VALIDATED |
| Cloud / SaaS exposure | CloudService (Sprint 017) | cloud account/org | provider/resources/exposure | `cloud-observations` | `cloud-normalizer` | `CanonicalObservation(cloud)` | provider detection + resource relationships | exposure → validated finding | proof cell `cloud_ownership_mapping`/`saas_analysis` | `CloudService` records, `FindingRecord` | `test_cloud_saas_mission.py`, `test_attack_surface_mission.py` | ✅ VALIDATED |
| Webhook weakness | CloudService, manual | SaaS integration | unsigned/unverified webhooks | `cloud-observations` | `cloud-normalizer` | webhook evidence | webhook relationships correlated | validated hypothesis → proven finding | proof cell `saas_analysis` | `CloudService` records, `FindingRecord` | `test_cloud_saas_mission.py` | ✅ VALIDATED |
| Novel behavior workflow | HypothesisLoopEngine, novel pipeline | observed behavior | classification | behavior normalizer | novel-pipeline stages | experiment + observation evidence | anomaly → hypothesis → experiment → proof candidate | novel validated | proof_ref on novel record | `NovelBehaviorRecord` | `test_vulnerability_research_mission.py` | ✅ VALIDATED |
| Out-of-band interaction | Interactsh | callback domain | callback records | `ssrf`/`oob` normalizer | `vulnerability-candidate-normalizer` | callback evidence | SSRF + OOB corroboration | validated hypothesis | — | `FindingRecord` | `test_vulnerability_research_mission.py` | ✅ VALIDATED |
| Proof replay | ProofReplayAdapter (`proof-replay`) | proof command | replayed behavior | proof adapter parse | replay normalizer | `REPLAY_RESULT`/`REPLAY_VERDICT` | replayed proof → PROVEN | replay verified | proof replay | `ReplayRecord` | `tests/golden/full_assessment/*.json` | ✅ VALIDATED |
| Mission dashboard | MissionDashboardService | mission id | overview/surface/evidence/proofs/tools | JSON projection | — | read-only aggregation | TIDB records + live aggregate | — | — | `MissionDashboardService.records` | `tests/integration/test_mission_dashboard_api.py`, `test_mission_dashboard_cli.py` | ✅ VALIDATED |
| Mission CLI | `hunterx hunt` | objective + target | overview/status/surface/coverage/findings/evidence/proofs/paths/timeline | JSON renderer | — | CLI projection | — | — | — | — | `tests/integration/test_mission_dashboard_cli.py` | ✅ VALIDATED |

---

## 2. Cross-tool correlation contracts

| Inventory | Primary | Corroborating | Deduplication key |
|---|---|---|---|
| Subdomains | Subfinder | Amass, Assetfinder, Findomain | `sub:<name>` |
| Services | Nmap | Naabu, Masscan, RustScan | `svc:<ip>:<port>` |
| Web intel | HTTPx | WhatWeb, Nuclei | `url:<url>` |
| URLs | Katana | GAU, Waybackurls, Gospider | `url:<url>` |
| Parameters | Arjun | ParamSpider, Kiterunner | `param:<url>:<name>` |
| Secrets | Gitleaks | TruffleHog, SecretFinder | `secret:<value-hash>` |
| API inventory | Kiterunner | Arjun, Katana, HTTPx | `endpoint:<url>` |
| GraphQL | InQL | GraphQLmap | `graphql:<endpoint>` |

---

## 3. Validation, proof and quality gates

Every finding passes the deterministic lifecycle `CANDIDATE → SUPPORTED →
VALIDATION_REQUIRED → VALIDATING → VALIDATED → PROOF_REQUIRED → PROVING →
PROVED → REPORT_READY` (with `DISPUTED` / `DISPROVED` / `DUPLICATE` /
`OUT_OF_SCOPE` / `REJECTED` terminal states) via
`FindingLifecycleStateMachine` (`domain/vulnerability_finding/lifecycle.py`).
Proof/PoC generation and replay are driven by `SafeProofGenerator` +
`ReplayEngine` (`domain/vulnerability_proof/`) and the `proof-replay` tool
adapter. Report quality is gated by `FindingQualityEngine`
(`domain/reporting/quality.py`) and `ReportabilityEngine`.

### False-positive performance

| Scenario | Detection | Validation | Result |
|---|---|---|---|
| XSS inert reflection | Dalfox candidate | not exploitable | **Rejected** (negative evidence) |
| Privilege escalation single-tool claim | candidate | no corroboration | **Rejected** |
| Schema exposure single-tool claim | candidate | not reachable | **Rejected** |
| Fake secret decoy | TruffleHog candidate | not live | **Rejected** |
| Decoy endpoint `/backup.zip` | FFUF hit | empty content | **Rejected** |
| Webhook ambiguity | candidate | unverifiable signature | **Inconclusive** (retained) |

The principle enforced throughout: **DETECTION != VALIDATION**.

---

## 4. Mission classes validated

| Mission | Objective | Acceptance test | Golden dataset | Key validated behaviors |
|---|---|---|---|---|
| Bug bounty | `bug_bounty_hunt` | `test_bug_bounty_mission.py` | `bug_bounty.json` | SQLi proven; XSS rejected; tool failure recovered; hidden endpoint via JS; cascade |
| Web pentest | `web_application_assessment` | `test_web_pentest_mission.py` | `web_pentest.json` | IDOR + session fixation proven; privesc rejected; behavior-based reasoning |
| API security | `api_assessment` | `test_api_security_mission.py` | `api_security.json` | GraphQL introspection + BOLA proven; schema claim rejected |
| External attack surface | `external_attack_surface` | `test_attack_surface_mission.py` | `attack_surface.json` | unified surface graph; multi-step attack path; cloud exposure proven |
| Cloud/SaaS | `cloud_assessment` | `test_cloud_saas_mission.py` | `cloud_saas.json` | Azure detection; blob exposure + webhook proven; fake secret rejected |
| Vulnerability research | `vulnerability_research` | `test_vulnerability_research_mission.py` | `vulnerability_research.json` | SQLi + SSRF + SSTI proven; novel behavior workflow |
| Red-team recon | `red_team_assessment` | `test_red_team_recon_mission.py` | `red_team_recon.json` | multi-step attack path; authorization bypass proven; cascade |

---

## 5. Failure recovery, substitution and consensus

- **Tool failure**: a crashed tool records `blocked` negative evidence and the
  mission continues (`amass` in the bug-bounty mission).
- **Tool substitution**: capability-equivalent fallback via
  `ToolFallbackResolver` (Nmap → Naabu/Masscan/RustScan) — capability-based,
  never hardcoded tool replacement.
- **Multi-tool consensus**: independent tools corroborate findings
  (Subfinder+Assetfinder, Nuclei+SQLmap+differential), and contradictory
  results are **preserved** as `ConflictingToolEvidence` — never averaged.

---

## 6. Operator visibility

- **Dashboard API**: `GET /missions/{id}/overview`, `/attack-surface`,
  `/coverage`, `/hypotheses`, `/findings`, `/evidence`, `/proofs`,
  `/attack-paths`, `/tools`, `/timeline`.
- **CLI**: `hunterx hunt`, `hunt status`, `hunt surface`, `hunt coverage`,
  `hunt findings`, `hunt evidence`, `hunt proofs`, `hunt paths`, `hunt timeline`.

---

## 7. Test surface

- Acceptance: `tests/acceptance/full_assessment/` (7 mission classes).
- Golden: `tests/golden/full_assessment/` (7 datasets) + `test_full_assessment_golden.py`.
- Integration: `tests/integration/test_mission_dashboard_api.py`,
  `tests/integration/test_mission_dashboard_cli.py`.
- Existing suites remain green (unit/component/architecture/integration/golden/
  security/acceptance/performance/engineering).

---

## 8. Status legend

| Status | Meaning |
|---|---|
| ✅ VALIDATED | Proven by a green deterministic test |
| 🧪 PARTIAL | Requires an installed external binary/service to fully exercise |
| 📋 CONTRACTED | Declared contract; offline replay verified |
