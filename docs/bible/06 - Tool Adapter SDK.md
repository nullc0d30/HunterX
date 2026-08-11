# 06 — Tool Adapter SDK

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** All tool integrations, `tools/<tool-id>/adapter.py`
**Schema:** `config/plugin.schema.yaml` (adapter plugins), `07 - Tool Knowledge Base Specification.md`

---

## 1. Purpose

The Tool Adapter SDK defines the **contracts** that every integrated tool
must satisfy to be executable, parseable, and reasoned about by HunterX.
Adapters are the bridge between the platform and an arbitrary external tool
(binary, library, remote service).

An adapter has exactly one job: **execute a tool in a standard, safe, and
observable way and produce canonical output.** Parsing/normalization happen in
separate, adapter-owned components (`parser.py`, `normalizer.py`) so that the
adapter stays focused.

---

## 2. Adapter Taxonomy

| Adapter | Responsibility | Typical tools |
|---------|----------------|---------------|
| `BaseAdapter` | Common contract every adapter implements | — (abstract) |
| `ScannerAdapter` | Active scanning / detection | nmap, nuclei, sqlmap, nikto, wpscan |
| `CrawlerAdapter` | Web crawling / link discovery | wget, hakrawler, gobuster (dir) |
| `EnumeratorAdapter` | Asset/intelligence enumeration | subfinder, amass, massdns, dnsx, certsh |
| `AnalyzerAdapter` | Analysis of provided input | semgrep, bandit, trivy, kube-hunter |
| `ReporterAdapter` | Consumes results to produce artifacts | (custom format exporters) |
| `ValidationAdapter` | Confirms/refutes a finding (PoC) | sqlmap (verify), nuclei -validate, custom PoC |

A single integration may implement multiple adapter types (e.g., `nuclei` as
both `ScannerAdapter` and `ValidationAdapter`).

---

## 3. Common Contract (`BaseAdapter`)

Every adapter must implement:

| Method | Purpose |
|--------|---------|
| `execute(request: ToolRequest) -> ToolResult` | Run the tool for the given request |
| `parse(output: bytes) -> Iterable[ParsedItem]` | Convert raw output to structured items |
| `normalize(items) -> Iterable[CanonicalEvent]` | Map parsed items to canonical entities |
| `validate(items) -> ValidationReport` | Sanity-check normalized output |
| `healthcheck() -> HealthReport` | Is the tool installed/available/authorized? |
| `capabilities() -> set[Capability]` | What can this adapter do? |
| `describe() -> AdapterInfo` | Metadata for registry/UI |

Shared input/output types (defined in `hunterx.plugins.sdk`):

- `ToolRequest`: `target_id`, `scope` (envelope), `args` (safe argv), `env_allowlist`,
  `timeout_s`, `resource_limits`, `correlation_id`, `profile` (tool profile name).
- `ToolResult`: `exit_code`, `stdout`, `stderr`, `duration_ms`, `outcome`
  (SUCCESS/PARTIAL/FAILED/TIMEOUT/VIOLATED), `artifacts` (paths to raw outputs).
- `ParsedItem`: normalized seed structure with `source_line`, `raw` reference.
- `CanonicalEvent`: a typed event (`finding.created`, `service.discovered`, ...)
  conforming to `08 - Unified Security Schema.md`.

---

## 4. Adapter Lifecycle

```
discover (registry scan of tools/)
  → validate (knowledge.yaml + adapter import + healthcheck)
  → register (adapter catalog)
  → execute (per request)
       ├─ preflight (scope check, healthcheck, secret binding)
       ├─ sandbox run (process/container)
       ├─ capture output (streamed)
       ├─ parse
       ├─ normalize
       ├─ validate
       └─ emit CanonicalEvents + ToolResult
  → unload (on removal/update)
```

---

## 5. `ScannerAdapter`

Contract additions:

```python
class ScannerAdapter(BaseAdapter):
    def scan(self, request: ScanRequest) -> ScanResult: ...   # convenience wrapper
    def discover(self, request: ScanRequest) -> Iterable[ServiceFinding]: ...
```

- Declares which **detection classes** it can confirm (from the tool knowledge file).
- `ScanResult` aggregates `ToolResult` + parsed findings + performance stats.
- Must honor `request.scope` (targets/ports/paths) exactly; overscope → VIOLATED.

---

## 6. `CrawlerAdapter`

Contract additions:

- `crawl(seed_urls) -> Iterable[UrlDiscovered]`
- Produces canonical `URL`, `Endpoint`, `Directory`, `Parameter` events.
- Respects robots/allow-rules per mission profile (configurable; default obey).
- Bounds: `max_depth`, `max_pages`, `same_origin`, `concurrency`.

---

## 7. `EnumeratorAdapter`

Contract additions:

- `enumerate(target, mode) -> Iterable[AssetDiscovery]`
- Produces `Domain`, `Subdomain`, `Host`, `IP`, `Certificate` events.
- `mode` values: `passive`, `active-light`, `active-full`, `bruteforce` — each
  gated by mission profile approval level.

---

## 8. `AnalyzerAdapter`

Contract additions:

- `analyze(inputs: AnalyzeInput) -> Iterable[AnalysisFinding]`
- `inputs` may be source code (SAST), container image, config, IaC.
- Produces `Finding` + optional `Technology`/`Misconfiguration` events.
- Never mutates inputs; read-only analysis.

---

## 9. `ReporterAdapter`

Contract additions:

- `render(report_models: ReportBundle) -> ReportArtifact`
- Consumes **canonical report models only** (never raw findings) to produce an
  output artifact (e.g., custom JSON-Lines export, CSV).
- Registered with the Reporting Engine renderer registry by format name.

---

## 10. `ValidationAdapter`

Contract additions:

- `validate(finding: Finding, evidence: Evidence) -> ValidationVerdict`
- Verdict: `CONFIRMED`, `REFUTED`, `INCONCLUSIVE`, `PARTIAL`.
- May run a PoC against a **copy/lab** or with explicit operator approval for
  destructive checks (per mission profile).
- Returns structured `ValidationResult` with reproduction steps + evidence refs.

---

## 11. Adapter & Tool Knowledge Integration

An adapter MUST be paired with a Tool Knowledge File (`07 - Tool Knowledge
Base Specification.md`). The knowledge file is the *contract of record* for:

- Which CLI syntax to emit (safe argv builder).
- Supported modes/profiles the adapter can request.
- Expected output formats (which parsers to apply).
- Error code → `outcome` mapping (normalize errors).
- Performance expectations (rate limits, timeouts).
- AI usage rules (what the AI may do with this tool's results).

The adapter references knowledge via `describe()['knowledge_id']` and the
`ToolExecutor` (see `02 - Architecture.md` §5.9) resolves and binds them.

---

## 12. Safety Contract (mandatory for all adapters)

1. **No direct `subprocess` from adapter code.** All execution goes through
   `tools/sandbox.py` (the sandboxed executor).
2. **Args are structured** (argv lists), never shell strings. No `sh -c`.
3. **Scope enforcement:** adapter must check every target/port/path against the
   scope envelope *before* invocation; any deviation → `VIOLATED` outcome, no run.
4. **Timeouts & limits** are always applied (from request, not adapter defaults).
5. **Secrets:** credentials are injected by the sandbox from `SecretPort` by
   declared names; never accepted as free-form argv.
6. **Destructive actions** (sqlmap `--dbs` on live DB, payload writes) require
   the mission profile's `destructive_allowed` flag; otherwise blocked at the
   executor.
7. **Observability:** every execution emits `tool.started`, `tool.completed` /
   `tool.failed` with correlation id, duration, outcome, and artifacts.
8. **Isolation:** untrusted tool output is never evaluated/executed; it is
   parsed by declarative parsers only.

---

## 13. Error Handling Contract

- Adapter raises `AdapterError` subclasses: `ToolMissingError`, `ToolTimeoutError`,
  `ToolCrashedError`, `ScopeViolationError`, `ParseError`, `UnsupportedModeError`.
- Each carries a machine code (see `17 - Error Handling Standards.md`) and is
  mapped to a `ToolResult.outcome`.
- Retryability is declared per error class: transient (retryable) vs permanent.
- Healthcheck failures degrade gracefully: the tool is marked unavailable and
  the workflow routes around it (see `17` §Graceful Degradation).

---

## 14. Versioning & Compatibility

- Adapters use SemVer; a tool's adapter version is independent of the tool's
  version (the knowledge file binds `tool_version` ranges).
- `healthcheck()` reports tool version; executor compares against
  `knowledge.tool.supported_versions` and warns on mismatch.
- Adapter ABI is versioned via `sdk_min` in the manifest.

---

## 15. Packaging

Each adapter ships in `tools/<tool-id>/`:

```
adapter.py        # implements one or more contracts above
parser.py         # parser for tool output (streamed)
normalizer.py     # canonical mapping
knowledge.yaml    # Tool Knowledge File (mandatory)
workflows.yaml    # workflow position rules
mission_rules.yaml# mission applicability
ai_rules.yaml     # AI usage rules
tests/            # adapter/parser/normalizer tests
README.md         # tool documentation
```

Full checklist: `22 - Tool Integration Standard.md`.

---

## 16. Testing an Adapter

- Unit: execute with canned outputs (fixtures), assert parse/normalize.
- Integration: run real tool binary (marked, skippable in CI without tools).
- Golden: known-good tool outputs → expected canonical events.
- Security: overscope argv rejected; shell injection attempt neutralized;
  secrets never leaked into stdout/errors.
- See `15 - Testing Standards.md`.

---

## 17. References

- `02 - Architecture.md` §5.9 (Tool SDK & Adapter Layer)
- `07 - Tool Knowledge Base Specification.md` (paired knowledge contract)
- `22 - Tool Integration Standard.md` (full integration checklist)
- `13 - Security Standards.md` (sandbox & execution security)
