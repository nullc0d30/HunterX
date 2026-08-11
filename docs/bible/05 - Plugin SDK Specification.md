# 05 — Plugin SDK Specification

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** Plugin authors, Plugin Host, Registry, Marketplace
**Schema:** `config/plugin.schema.yaml`

---

## 1. Purpose & Scope

The Plugin SDK defines how third parties extend HunterX **without modifying the
core**. A plugin is a versioned, signed, self-contained package that implements
one or more **extension points** via a stable public ABI.

Supported plugin types:

| Plugin type | Extends | Example |
|-------------|---------|---------|
| `detector` | Detection during a mission | Custom WAF detector |
| `hook` | Event reactions (pre/post) | Slack notification on `finding.created` |
| `reporter` | Report formats/views | Custom CSV export |
| `skill` | Reusable security procedure | SSH brute-force-then-validate skill |
| `adapter` | New tool integration | Adapter for a scanner binary |
| `ai-strategy` | Planner/reasoner behavior | Custom consensus strategy |
| `auth-provider` | API auth backends | SAML/OIDC adapter |
| `mission-profile` | New assessment type | Kubernetes-specific profile |
| `parser` | New output format parser | Custom JSON-Lines parser |
| `normalizer` | New canonical mapping | Vendor-specific technology mapping |

**Constraints:** plugins must not import private internals of `src/hunterx`.
Only the public SDK (`hunterx.plugins.sdk`) is available.

---

## 2. Plugin Lifecycle

```
manifest written
  → VALIDATED        (schema + dependency check)
  → SIGNED           (signature required for full trust)
  → REGISTERED       (catalogued in Registry)
  → INSTALLED        (files placed in managed plugin store)
  → LOADED           (imported into isolated host, permissions bound)
  → EXECUTING        (active; hooks/detectors fire)
  → UPDATED          (new version replaces old; migration hooks run)
  → UNLOADED         (clean shutdown, resources released)
  → REMOVED          (uninstalled; data retention per policy)
  → (BANNED)         (quarantine after security incident)
```

State diagram:

```
           validate ──► signed ──► registered ──► installed ──► loaded ──► executing
              │                                          ▲             │
              ▼                                          │             ▼
          REJECTED ───────────────────────────────► unloaded ◄──► updated
                                                       │
                                                       ▼
                                                  removed / banned
```

### 2.1 Lifecycle Events

| Event | Emitted when | Payload |
|-------|--------------|---------|
| `plugin.validated` | Manifest passes schema + deps | `plugin_id`, version |
| `plugin.signed` | Signature verified | `plugin_id`, signer |
| `plugin.registered` | Added to registry | `plugin_id` |
| `plugin.installed` | Files deployed | `plugin_id`, path |
| `plugin.loaded` | Host initialized | `plugin_id`, permissions |
| `plugin.executing` | Active | `plugin_id`, hooks |
| `plugin.updated` | Version replaced | `from`, `to` |
| `plugin.unloaded` | Clean shutdown | `plugin_id` |
| `plugin.removed` | Uninstalled | `plugin_id` |
| `plugin.banned` | Quarantined | `plugin_id`, reason |
| `plugin.rejected` | Validation failure | `plugin_id`, errors |

---

## 3. Plugin Manifest (`plugin.yaml`)

Validated against `plugin.schema.yaml`. Example:

```yaml
api_version: "1.0"
id: com.example.sec.slack-notifier
name: Slack Notifier
description: Posts finding events to a Slack channel.
version: 1.4.2          # SemVer
type: hook
author:
  name: Example Corp
  email: security@example.com
  url: https://example.com
license: Apache-2.0
python_requires: ">=3.11,<3.14"
engine_compatibility:
  core_min: "6.0.0"
  core_max: "7.0.0"
sdk_min: "1.0.0"
dependencies:
  - id: com.example.sec.http
    version: ">=2.0.0"
  - python: { requests: ">=2.28" }
permissions:
  network: [outbound-https]     # capability-based
  filesystem: { read: [], write: [] }
  process: { execute: false }
  secrets: [SLACK_WEBHOOK_URL]
entry_points:
  hooks:
    - event: finding.created
      handler: plugin:handle_finding
      priority: 100
resources:
  max_memory_mb: 256
  max_runtime_s: 60
signing:
  key_id: "0123..."
  algorithm: ed25519
  signature: "base64..."
```

### 3.1 Mandatory Fields

`api_version`, `id`, `name`, `version`, `type`, `author`, `license`,
`python_requires`, `sdk_min`, `entry_points`, `permissions`.

`id` must be reverse-DNS and globally unique. `version` is SemVer 2.0.0
(major.minor.patch[+build]).

---

## 4. Registration

- Registration happens at **startup scan** (plugin store directories) and
  **runtime install** (`hunterx plugin install <src>`).
- Registry maintains the active catalog: `plugin_id → manifest + state + hash`.
- No two plugins may claim the same `id`; a version conflict between two plugins
  requiring incompatible `core`/`sdk` ranges is a **hard conflict** → the later
  one is rejected with a clear error.
- Registration is **idempotent**: re-registering the same `(id, version)` is a no-op.

---

## 5. Loading & Hosting

- Plugins load into an **isolated runtime** (subprocess host by default;
  container host for untrusted plugins). The core talks to the host over the
  host ABI (JSON messages or IPC), never direct imports for untrusted code.
- Loading sequence:
  1. Verify signature (if present) against trusted keys.
  2. Validate manifest again (defense in depth).
  3. Instantiate the host with declared permissions.
  4. Import entry-point modules; bind handlers.
  5. Call `on_load(context)`; on exception → `plugin.rejected`, plugin disabled.
- Load failures are non-fatal to the core; the plugin is marked `disabled`
  with the error recorded.

---

## 6. Execution Model

- Hooks and detectors receive a **`PluginContext`** with: scope envelope,
  correlation id, mission id, read-only domain views, and typed request/response
  primitives.
- Execution is bounded: `resources.max_runtime_s`, `max_memory_mb` enforced by
  the host. Violation → kill + `plugin.banned` (transient) or downgrade.
- Hooks run synchronously per event but may schedule async work; the host
  enforces the deadline.
- Return contract: hooks return an optional `PluginResult` (continue/abort/
  modify). Detectors return `DetectorResult` (boolean + evidence).
- Errors: plugin errors are isolated; a throwing hook never crashes the core.
  The event is logged with the plugin id and `correlation_id`.

---

## 7. Permissions Model

Capability-based, declared in the manifest and enforced by the host:

| Capability | Meaning |
|-----------|---------|
| `network.outbound-https` | HTTPS to declared domains only |
| `network.outbound-any` | Arbitrary outbound (never granted to untrusted plugins) |
| `network.bind` | Listening sockets (quarantined by default) |
| `filesystem.read` | Read paths (patterns) |
| `filesystem.write` | Write paths (patterns) |
| `process.execute` | Spawn processes (default off) |
| `secrets.get:<NAME>` | Access specific secret keys |
| `ai.invoke` | Use the AI abstraction (rate-limited) |
| `db.query:<SCOPE>` | Read-only domain queries |

Rules:

- Deny-by-default: omitted capability = denied.
- Scoped paths/domains; wildcards require explicit justification in manifest review.
- Permissions are bound at load time and immutable for the session.
- Privilege escalation attempt → `plugin.banned` + audit event.

---

## 8. Dependencies

- `dependencies` may reference other plugins (by `id` + version range) and
  Python packages.
- Resolution at install/load: satisfies ranges, detects conflicts, produces a
  deterministic resolution graph.
- Plugins cannot load if a dependency is missing or incompatible; error lists
  the missing/incompatible item.
- Python package dependencies install into the plugin's own environment
  (venv or container), never the core environment.

---

## 9. Validation

Two layers:

1. **Schema validation** (install time): manifest against
   `plugin.schema.yaml`; failure → reject with line-level errors.
2. **Behavior validation** (load time): entry points resolve, handlers are
   callable with the expected signature, permissions are consistent.
3. **Sandbox validation** (CI/publish time, for marketplace): automated
   `plugin test` runs in a container with a safety harness (see
   `15 - Testing Standards.md`).

---

## 10. Versioning

- SemVer 2.0.0 strictly. Breaking manifest/entry-point changes require a
  **major** bump of the *SDK* and a bump of `sdk_min`/`api_version` in plugins.
- Core engine compatibility is expressed by `engine_compatibility.core_min/max`.
- On `plugin.updated`, the host runs optional `migrations:` hooks (from the new
  manifest) before switching versions.

---

## 11. Removal

- `hunterx plugin remove <id>` → `unload → remove files → purge registrations`.
- Removal is transactional: if unload fails, files remain and the plugin is
  marked `remove-pending`.
- Data created by a plugin is retained per `data retention` policy
  (see `09 - Database Design.md` §Retention); removal does not cascade-delete
  evidence or findings that are still referenced.

---

## 12. Updates

- `hunterx plugin update <id>` resolves the newest compatible version from the
  marketplace or local source.
- Update is atomic: new version validates in a staging host first; on success,
  old version unloads, new loads; on failure, old version remains active.
- Rolling back to a previous version is supported (`hunterx plugin pin`).

---

## 13. Security

| Control | Requirement |
|---------|-------------|
| Signing | Recommended for all; **required** for any plugin requesting `network`, `process`, or `secrets` |
| Integrity | SHA-256 of plugin archive verified at install |
| Provenance | Marketplace records maintainer + signing key history |
| Supply chain | Dependencies pinned; rebuilds verified (SLSA level ≥1) |
| Isolation | Subprocess/container host; no shared memory with core |
| Secrets | Only declared `secrets.<NAME>` keys injected; host redacts at boundaries |
| Audit | Every lifecycle event, permission grant, and execution is audited |
| Quarantine | `hunterx plugin ban <id>` disables immediately and flags for review |
| Rate limits | `ai.invoke` and `network` capabilities are rate-limited per plugin |
| Malicious input | Plugin output is schema-validated; never eval/exec from output |

See `13 - Security Standards.md` for the global security model.

---

## 14. Plugin Development Workflow (for authors)

1. `hunterx plugin scaffold <id> --type hook` generates a compliant skeleton.
2. Fill manifest + handlers; keep to the public SDK.
3. `hunterx plugin test <dir>` runs schema validation + behavior harness.
4. `hunterx plugin package <dir>` builds the signed archive.
5. `hunterx plugin install <archive>` installs locally.
6. Publish to the marketplace (if desired) via the community pipeline.

---

## 15. Public SDK Surface (summary)

The SDK exposes (namespaced, stable, versioned):

- `Plugin` base class, `PluginContext`, `PluginResult`, `DetectorResult`.
- Event constants for all hookable events.
- Read-only domain views (`TargetView`, `FindingView`, `EvidenceView`).
- Capability enum and permission helpers.
- Typed request/response primitives for hooks and skills.
- `on_load`, `on_unload`, `health()` hooks.

Anything not in this surface is **private** and may change without notice.

---

## 16. References

- `02 - Architecture.md` §5.8 (Plugin System)
- `06 - Tool Adapter SDK.md` (adapter plugins)
- `13 - Security Standards.md` (sandbox & integrity)
- `15 - Testing Standards.md` (plugin testing harness)
- `22 - Tool Integration Standard.md` (tool→plugin relationship)
