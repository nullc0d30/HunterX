# 07 — Tool Knowledge Base Specification

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** Every integrated tool's `tools/<tool-id>/knowledge.yaml`
**Schema:** `config/knowledge.schema.yaml`

---

## 1. Purpose

Every integrated tool MUST have a structured **knowledge file** — a YAML
document that is the single machine-readable source of truth about how to
invoke, parse, reason about, and govern a tool. The knowledge file is read by
the Planner, the AI Engine, the Workflow Engine, the Tool Executor, and the
Reporting Engine.

A tool without a valid knowledge file is **not integrated** and cannot be
scheduled by any mission.

---

## 2. File Location & Naming

- Location: `tools/<tool-id>/knowledge.yaml`
- `<tool-id>`: lowercase, `[a-z0-9-]+` (e.g., `nuclei`, `sqlmap`, `subfinder`).
- The `id` field inside the file MUST equal the directory name.

---

## 3. Required Metadata (top level)

```yaml
id: nuclei                    # MUST equal directory name
name: Nuclei                  # Human-readable
vendor: ProjectDiscovery
homepage: https://github.com/projectdiscovery/nuclei
license: MIT
tool_type: scanner            # scanner|crawler|enumerator|analyzer|reporter|validator|multi
adapter: nuclei               # adapter plugin id (see 06)
adapter_version: "1.2.0"      # SemVer of our adapter
tool_versions:
  min: "3.0.0"
  max: null                   # null = no upper bound
  recommended: "3.2.0"
installation:
  method: binary              # binary|pip|docker|plugin|system
  instructions: "https://github.com/projectdiscovery/nuclei#installation"
  verify: "nuclei -version"
tags: [web, vulnerability, dast]
```

---

## 4. Capabilities

```yaml
capabilities:
  - id: vulnerability-scan
    description: Template-driven vulnerability scanning of web endpoints
  - id: cve-detection
    description: Detect CVEs from community templates
  - id: http-crawl
    description: Crawl web roots to discover endpoints (uncover/external)
  - id: tech-fingerprint
    description: Detect technologies via template probes
```

Each capability maps to one or more mission phases and is used by the Planner
to select tools. Capabilities must be stable and shared across tools
(registry `tools/index.yaml` keeps the shared vocabulary).

---

## 5. CLI Syntax Model

Never store raw shell templates. Model syntax structurally so the executor can
build safe argv lists.

```yaml
cli:
  binary: nuclei
  executable_env: PATH        # where to resolve the binary
  invocation:
    base: [-templates, <profile>]      # always-present safe defaults
    target_flag: -u                    # flag accepting the target
    target_position: flag              # flag|positional
  profiles:                            # named run configurations
    fast:
      args: [-timeout, "10", -rate-limit, "50", -silent]
      timeouts: { per_request_s: 10, total_s: 600 }
      rate_limit: { rps: 50, max_concurrent: 10 }
    thorough:
      args: [-timeout, "30", -rate-limit, "200"]
      timeouts: { per_request_s: 30, total_s: 3600 }
      rate_limit: { rps: 200, max_concurrent: 50 }
  output:
    stdout_parser: nuclei-jsonl
    stderr_parser: nuclei-jsonl
    file_formats: [jsonl, html, md]
    flag_output: -o
  env:
    allowlist: [NUCLEI_GITHUB_TOKEN]
  destructive: false
```

Rules:

- `destructive: true` requires explicit operator approval before any run.
- Every profile must define `timeouts` and `rate_limit` (never unbounded).
- `args` values are literals or safe placeholders; no `$(...)`, `;`, `|` shells.

---

## 6. Supported Modes

```yaml
modes:
  - id: single-target
    inputs: [url, domain]
    params: { templates: string, severity: "info|low|medium|high|critical" }
  - id: bulk-list
    inputs: [file:list]
    params: { concurrency: int }
```

Each mode declares accepted `inputs` (from canonical types) and its parameters.
The executor validates `mode` + `params` against this section before running.

---

## 7. Input Contract

```yaml
inputs:
  accepts:
    - url
    - domain
    - endpoint
  required: [url]
  optional: [headers, cookies_from_session, auth_profile]
  transforms:
    - canonicalize-url
  max_targets_per_invocation: 100
```

---

## 8. Output Contract

```yaml
output:
  formats:
    jsonl:
      parser: nuclei-jsonl
      fields:
        - template-id
        - matched-at
        - severity
        - info
        - curl-command
  normalizer: nuclei
  event_types: [finding.created, technology.discovered, service.discovered]
  evidence_capture: [raw_request, raw_response, matched_text]
  dedup_key_spec: [matched-at, template-id, severity]
```

The parser must map raw output to `ParsedItem`s; the normalizer maps to
canonical events (`08 - Unified Security Schema.md`). `dedup_key_spec` defines
the fields used to derive the canonical finding hash.

---

## 9. Dependencies

```yaml
dependencies:
  binaries: []                # required external binaries (beyond the tool)
  network: { egress: [https], dns: true }
  runtime: [docker]           # docker|python|java|go|none
  data:                       # data the tool needs to function
    - id: nuclei-templates
      type: git-mirror
      source: https://github.com/projectdiscovery/nuclei-templates
      sync: on-install
```

---

## 10. Error Codes

```yaml
errors:
  mapping:
    exit_1: { outcome: FAILED, retryable: true, message: "generic runtime error" }
    exit_2: { outcome: FAILED, retryable: false, message: "invalid arguments" }
    exit_130: { outcome: TIMEOUT, retryable: true, message: "interrupted" }
  stderr_patterns:
    - pattern: "no results found"
      outcome: SUCCESS_EMPTY
    - pattern: "unauthorized"
      outcome: AUTH_FAILED
```

Every mapped code produces a `ToolResult.outcome`; unmapped exits default to
`FAILED` with the raw exit code retained.

---

## 11. Performance

```yaml
performance:
  expected_duration: { per_target_s: 120, scale: linear }
  memory: { typical_mb: 512, max_mb: 2048 }
  rate_limit_guidance: { default_rps: 100, polite_rps: 20 }
  concurrency: { supported: true, default: 10, max: 50 }
  best_run_window: off-peak
```

These feed the Performance Engine and scheduler decisions
(`14 - Performance Standards.md`).

---

## 12. Profiles

Profiles (see §5 `cli.profiles`) must cover at least:
`fast`, `thorough`, `stealth`, `quiet`. Each profile documents timeouts, rate
limits, and verbosity. Mission profiles select a tool profile by name.

---

## 13. Examples

```yaml
examples:
  - name: Quick vuln scan of a URL
    mode: single-target
    params: { templates: critical, severity: high }
    args: [-u, "https://example.com", -severity, high]
  - name: Bulk scan from list
    mode: bulk-list
    params: { concurrency: 20 }
    args: [-l, "<list_file>", -rate-limit, "100"]
```

Examples are used for smoke tests and documentation generation.

---

## 14. Workflow Position

```yaml
workflow:
  phases: [detection, validation]
  prerequisites:
    - requires: [recon.domains-resolved, recon.services-open]
  produces:
    - finding
    - technology
  blocks: null
  typical_sequence: after-port-scan
  recommended: true
```

Tells the Workflow Engine where the tool fits, what it needs, and what it
produces. See `10 - Workflow Engine.md`.

---

## 15. Mission Rules

```yaml
mission_rules:
  applicable: [bug-bounty, web-security, api-security, external-pentest, continuous]
  not_applicable: [cloud-security, mobile-security]
  per_mission_overrides:
    api-security:
      allowed_modes: [single-target]
      approval: operator
  approval_level: auto        # auto|operator|destructive-approval
  auth_profiles: [none, header, cookie]
```

Defines which missions may use this tool and with what approval level.

---

## 16. AI Usage Rules

```yaml
ai:
  allowed: true
  purposes:
    - triage-findings
    - select-templates
    - draft-evidence-notes
  disallowed:
    - generate-payloads-from-scratch     # tool must be used
    - auto-run-without-approval
  grounding:
    required_context: [scope, findings-summary, templates-meta]
    context_limit_tokens: 8000
  output_usage:
    - feeding-planner
    - report-drafting
  risk:
    hallucination_warning: "AI must not invent findings; findings require tool evidence"
```

Enforced by `11 - AI Standards.md`. If `allowed: false`, the AI never reasons
about this tool's output.

---

## 17. Best Practices

```yaml
best_practices:
  - "Use -rate-limit to stay polite; never hammer targets"
  - "Always pin template versions for reproducible scans"
  - "Combine with validation adapter before reporting critical findings"
```

Displayed to operators via `hunterx tool docs <tool-id>` and used to seed
planner heuristics.

---

## 18. Validation Requirements

The knowledge file MUST:

- Validate against `config/knowledge.schema.yaml` (CI + load time).
- Reference a parser and normalizer that exist and have tests.
- Reference an adapter that satisfies `06 - Tool Adapter SDK.md`.
- Declare at least one profile and one mode.
- Declare timeouts and rate limits on every profile.
- Not contain secrets.

---

## 19. References

- `06 - Tool Adapter SDK.md` (adapter contract the knowledge file describes)
- `22 - Tool Integration Standard.md` (full integration checklist)
- `08 - Unified Security Schema.md` (canonical event types used above)
- `02 - Architecture.md` §5.6 (Knowledge Base)
