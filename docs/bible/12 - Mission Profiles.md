# 12 — Mission Profiles

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** `config/profiles/<id>.yaml`, Mission Engine, Planner, Workflow, Reporting

---

## 1. Purpose

A **Mission Profile** is the declarative definition of a complete assessment
type. It binds together: workflow phases, objectives, allowed tools, expected
outputs, reports, and the risk model. Profiles are data (`YAML`), validated
against a JSON Schema, and versioned.

The twelve supported profiles are enumerated in `01 - Vision.md` §6.

---

## 2. Profile Schema (common structure)

```yaml
id: external-pentest          # stable identifier
version: 1
name: External Penetration Test
description: Perimeter-focused pentest of internet-facing assets.
supported_targets: [domain, ip, cidr, url]
phases:
  - id: recon
    name: Reconnaissance
    steps: <workflow steps, see 10 - Workflow Engine>
objectives:
  - "Identify internet-facing attack surface"
  - "Discover exploitable vulnerabilities with PoC"
allowed_tools:
  include: [subfinder, dnsx, nmap, nuclei, httpx, sqlmap, wpscan]
  exclude: [hydra]              # e.g., no brute-force by default
tool_profiles: { default: fast, stealth: quiet }
expected_outputs:
  findings: { min_severity: info }
  assets: [domain, host, ip, port, service, url]
  evidence: required
  reports: [technical, executive, evidence-package]
approval_level: operator        # auto|operator|destructive-approval
risk_model:
  formula: cvss-v3-base-v2      # risk model id
  weights: { exploitability: 0.4, impact: 0.4, exposure: 0.2 }
  escalation: { critical: alert, high: notify, low: silent }
compliance_map: [owasp-top10, pci-dss]
constraints:
  max_scan_duration_h: 24
  max_concurrency: 20
  default_timeouts: { per_request_s: 30 }
```

---

## 3. Cross-Cutting Profile Fields

| Field | Meaning |
|-------|---------|
| `supported_targets` | Target kinds this profile accepts |
| `phases` | Ordered workflow phases (see `10`) |
| `objectives` | Mission success criteria |
| `allowed_tools` | Include/exclude tool ids (vs `07` §15 mission_rules) |
| `tool_profiles` | Default tool run profiles (fast/thorough/stealth/quiet) |
| `expected_outputs` | Contract: what the mission MUST produce |
| `approval_level` | Human-approval requirement tier |
| `risk_model` | Formula + weights + escalation |
| `compliance_map` | Report mapping targets |
| `constraints` | Time, concurrency, timeout budgets |

---

## 4. The Twelve Mission Profiles

### 4.1 `bug-bounty`

- **Targets:** domain, url, api.
- **Phases:** scope-enforce → recon (passive→active) → enumerate (subdomains,
  endpoints, params) → detect (templates, manual checks) → validate (PoC,
  false-positive filter) → triage (dedup, severity) → report.
- **Objectives:** valid, reproducible, severity-ranked findings within the
  bounty scope.
- **Tools:** subfinder, dnsx, httpx, nuclei, katana, ffuf, sqlmap, wpscan,
  nikto, burp-community (optional).
- **Outputs:** findings (with PoC evidence), per-asset risk, technical report.
- **Risk model:** CVSS base + bounty context (exposure to internet).

### 4.2 `web-security`

- **Targets:** url, endpoint.
- **Phases:** crawl → fingerprint → detect (OWASP Top 10) → validate → report.
- **Tools:** httpx, katana, nuclei, wpscan, nikto, sqlmap (validate), custom PoC.
- **Outputs:** endpoint map, tech stack, findings, evidence package.

### 4.3 `api-security`

- **Targets:** api, url.
- **Phases:** discover (specs, endpoints, params) → authn/authz review → fuzz
  (params, methods) → validate → report.
- **Tools:** katana, ffuf, nuclei (api templates), custom fuzzers, mitm-adjacent.
- **Outputs:** API inventory, auth findings, fuzz findings, SARIF.

### 4.4 `external-pentest`

- **Targets:** domain, ip, cidr, url.
- **Phases:** recon → port/service scan → vulnerability scan → exploitation-PoC
  → validation → reporting.
- **Tools:** subfinder, dnsx, nmap, httpx, nuclei, metasploit (PoC), sqlmap.
- **Risk model:** full CVSS + business impact.

### 4.5 `internal-pentest`

- **Targets:** ip, cidr, hostname.
- **Phases:** discovery → enumeration (services, shares) → credential attacks →
  lateral movement → escalation → persistence check → reporting.
- **Tools:** nmap, crackmapexec, impacket, enum4linux, bloodhound, hydra (with
  approval), responder.
- **Risk model:** prioritizes internal exposure and privilege paths.

### 4.6 `ad-assessment` (Active Directory)

- **Targets:** ad-domain, hostname.
- **Phases:** domain enumeration → trust mapping → attack-path discovery
  (bloodhound) → escalation (kerberoast, asrep, relay) → validation → reporting.
- **Tools:** bloodhound, impacket, crackmapexec, ldapsearch, certipy.
- **Risk model:** privilege path severity + domain trust impact.

### 4.7 `cloud-security`

- **Targets:** cloud-account, arn.
- **Phases:** inventory → IAM review → misconfiguration detection → exposure
  validation → reporting.
- **Tools:** scoutsuite, prowler, pacu, awscli/az/gcloud wrappers.
- **Risk model:** cloud exposure + IAM blast radius.

### 4.8 `container-security`

- **Targets:** container (image ref).
- **Phases:** image pull → vulnerability scan → registry scan → runtime
  (optional) → validation → reporting.
- **Tools:** trivy, grype, docker scan, clair.
- **Risk model:** image severity + runtime posture.

### 4.9 `kubernetes-security`

- **Targets:** cluster (kubeconfig), namespace.
- **Phases:** cluster enumeration → RBAC review → admission review → pod/network
  policy review → validation → reporting.
- **Tools:** kube-hunter, kube-bench, popeye, kubeaudit.
- **Risk model:** control-plane exposure + workload privilege.

### 4.10 `mobile-security`

- **Targets:** mobile-app (apk/ipa), repo.
- **Phases:** static analysis → manifest/cert review → dynamic (emulator) →
  traffic/storage review → validation → reporting.
- **Tools:** apkleaks, mobsf, objection, frida (dynamic), adb.
- **Risk model:** app data exposure + platform weaknesses.

### 4.11 `network-security`

- **Targets:** ip, cidr, hostname.
- **Phases:** discovery → port scan → service fingerprint → vuln scan →
  validation → reporting.
- **Tools:** nmap, masscan, openvas (optional), hydra (approval).
- **Risk model:** service exposure + reachability.

### 4.12 `continuous`

- **Targets:** any (recurring scope set).
- **Phases:** schedule-driven delta scans → drift detection → regression
  findings vs baseline → continuous report.
- **Tools:** inherits per-scope-set toolchains (profile composition).
- **Risk model:** trend-based; new/changed findings emphasized.
- **Notes:** uses the Scheduler (`02` §5.17); checkpoints and caching are
  heavily used; findings deduped against baseline.

---

## 5. Approval Levels

| Level | Meaning | Enforced |
|-------|---------|----------|
| `auto` | Runs without human in the loop | none beyond scope |
| `operator` | Mission start + destructive-class steps need approval | approval gate step (`10` §3) |
| `destructive-approval` | Any potentially destructive/impactful action needs explicit approval with justification | approval gate + scope policy |

Planner never bypasses the level; tool knowledge `mission_rules.approval_level`
(`07` §15) is the floor, and profile level is the ceiling.

---

## 6. Risk Models

### 6.1 Formula Framework

Risk is deterministic:

```
risk_score = Σ (weight_i × normalized_factor_i)
normalized factors: exploitability, impact, exposure, likelihood, detectability
clamped to [0,10]; severity derived per 08 §5
```

### 6.2 Default Models

| Model id | Basis | When |
|----------|-------|------|
| `cvss-v3-base-v2` | CVSS v3 base + exposure | most web/external |
| `cvss-v3-aug-internal` | CVSS + internal reachability | internal pentest |
| `ad-privilege-path` | privilege path + domain impact | AD assessment |
| `cloud-iam-blast` | IAM blast radius + data exposure | cloud |
| `image-and-runtime` | image severity + runtime posture | container/k8s |
| `mobile-data-exposure` | data exposure + platform | mobile |
| `continuous-trend` | delta + trend weighting | continuous |

Custom models are plugins (`ai-strategy`/custom risk model) per `05`.

---

## 7. Expected Outputs Contract

Each profile declares `expected_outputs`; the Mission Engine validates at
completion:

- Minimum set of report types generated (`21 - Reporting Standards.md`).
- Mandatory evidence for findings above a severity threshold.
- Asset inventory completeness thresholds (e.g., "port scan coverage of all
  live hosts").

Failure to meet the output contract → mission marked `completed-with-warnings`
(or `failed` if a mandatory artifact is absent).

---

## 8. Adding / Modifying Profiles

- Ship as data in `config/profiles/`; schema-validated; versioned (SemVer).
- Modifying a shipped profile → minor bump; breaking change → major + migration
  note.
- New profiles are a Schema Change + Mission Profile review
  (`24 - Quality Assurance.md`).

---

## 9. References

- `01 - Vision.md` §6 (supported assessment types)
- `10 - Workflow Engine.md` (phase/step execution)
- `07 - Tool Knowledge Base Specification.md` §15 (mission rules)
- `21 - Reporting Standards.md` (report views)
