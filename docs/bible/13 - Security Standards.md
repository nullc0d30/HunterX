# 13 — Security Standards

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** All code, plugins, adapters, execution, secrets, supply chain, audit

---

## 1. Security Posture

HunterX is a security product; it must **practice what it preaches**. Security
is a design property, not a feature. Every layer enforces: **least privilege,
isolation, defense in depth, and auditability**.

Threat model scope (primary assets to protect):
1. Operator credentials and secrets.
2. Engagement target data and evidence (confidentiality).
3. The platform's own integrity (supply chain, sandbox escape, injection).
4. Availability of the platform (abuse, DoS by tools/targets).

---

## 2. Secure Coding

- Follow `04 - Coding Standards.md` + the OWASP Secure Coding checklist.
- Input validation at **every boundary** (CLI, API, plugin, adapter, parser).
- Output encoding where content is rendered (reports/HTML).
- Path traversal, command injection, template injection, SSRF, XXE: all
  explicitly mitigated and covered by security tests.
- No `eval`/`exec` of tool output, plugin input, or AI output. Parsers are
  declarative; never `pickle.load` from untrusted sources.
- Deserialization of untrusted data restricted to allow-listed types
  (`json`, strict `yaml.safe_load`, `pydantic` with `from_attributes`).
- SQL via parameterized queries / ORM only; no string-built SQL.
- Dependencies pinned (exact or compatible ranges) with vulnerability scanning
  in CI (`pip-audit`/`trivy` for the lockfile).

---

## 3. Sandbox

All external process execution (tools, skills, plugins) goes through the
**Tool Execution Sandbox** (`02` §5.9, `06` §12).

| Layer | Control |
|-------|---------|
| Container | Run in an ephemeral container (no host mount unless required), read-only rootfs where possible, no privileged mode |
| Process | Resource limits: CPU, memory, fd, runtime deadline |
| Network | Egress to scope envelope only (allow-list via proxy/iptables); DNS to scoped targets |
| Filesystem | tmpfs workdir; only artifact output paths writable |
| User | Non-root execution user; capability drop |

Sandbox decisions are **documented per tool** in its knowledge file
(`07` §9, §12). Tools that cannot be sandboxed are either rejected or marked
`unsandboxed-requires-operator` and never run without explicit per-run approval.

Sandbox escape or scope violation → process killed, mission paused, incident
audit, quarantine of the offending tool/plugin.

---

## 4. Permissions & Least Privilege

- **RBAC** at the API/CLI/UI layer: roles (`viewer`, `operator`, `analyst`,
  `admin`) with scoped data access (per engagement/tenant).
- **Capability model** for plugins (`05` §7): deny-by-default.
- **Token scopes:** API keys carry explicit resource scopes; JWT carries
  engagement-limited claims.
- **Tool credential delivery:** sandbox injects only declared secrets; tools
  never receive master/vault tokens.

---

## 5. Secrets Management

- `SecretPort` abstraction: local encrypted keystore (default), Vault, or KMS.
- Secrets at rest: encrypted (AES-256-GCM; keys from KMS/vault, never in config).
- Secrets in transit: TLS 1.2+ for all platform channels.
- Secrets never appear in: logs, errors, reports, AI prompts, config dumps,
  trace spans, or API responses. Enforced by masking at boundaries + audit grep tests.
- Rotation: supported per secret; expires sessions/tokens on rotation.
- Static secrets in code/repos are **blocked** by pre-commit + CI secret-scanning
  (gitleaks/trufflehog).

---

## 6. Isolation

| Boundary | Isolation |
|----------|-----------|
| Process | Subprocess/container per tool run; no shared memory with core |
| Plugin | Plugin host isolation (`05` §5) |
| Tenant/Engagement | Data access scoped by engagement; cross-tenant queries impossible by design |
| Network | Platform segments: API, workers, DB, cache separated; no public DB |
| Filesystem | Per-mission artifact directories; evidence read paths controlled |

---

## 7. Tool Execution Security

- Every run bounded: timeout, resource limits, rate limit (from knowledge file).
- Destructive actions gated by `approval_level` and scope policy
  (`07` §15, `12` §5).
- Tool output treated as **untrusted data**; parsed, never executed.
- Poisoned output (prompt injection) is handled per `11` §12.
- Rate limiting to avoid target disruption (polite defaults).

---

## 8. Supply Chain

- Lockfiles committed; reproducible builds.
- CI verifies dependency hashes and runs CVE scanning on the lockfile.
- Plugins/adapter packages: signature verification (`05` §13) and provenance.
- Containers: minimal base images, non-root, distroless where feasible,
  image signing.
- SLSA level ≥1 for release artifacts; signed SBOM (CycloneDX) published.

---

## 9. Integrity & Cryptographic Controls

- All artifacts (evidence, reports, plugin archives) carry SHA-256; evidence
  integrity re-verified on read.
- Signing: plugin archives, release assets, report artifacts (optional).
- TLS: minimum TLS 1.2; strong cipher suites; HSTS for web UI.
- Secrets & tokens: hashed at rest (argon2id for passwords; sha256+pepper or
  HMAC for tokens).
- Key management: KMS-backed; keys versioned and rotated.

---

## 10. Audit Logging

- Append-only audit log (`09` `audit_log`): every auth, authorization decision,
  mission action, approval, permission grant, secret access, plugin lifecycle
  event, and data export.
- Fields: `correlation_id`, `actor`, `action`, `resource`, `result`, `detail`,
  `at`. Tamper-evidence: hash-chaining or WORM storage in enterprise mode.
- Audit log is **never** part of user-deletable data; retention per policy.
- Audit log itself is read-restricted (admin/auditors only).

---

## 11. API & Network Security

- AuthN: API key, OAuth2/OIDC, mTLS, local (per `20 - REST API Standards.md`).
- AuthZ: RBAC at every route; engagement-scoped data filters.
- Rate limiting + quota per user/token/IP.
- Input validation (pydantic schemas); no HTML in error messages.
- CSRF protection for cookie-auth UI; CORS allow-list; security headers.
- Payload size limits; request timeouts; no unbounded uploads.

---

## 12. Data Security (at rest / in use)

- DB: encryption at rest (disk/volume), encrypted backups.
- Evidence blobs: server-side encryption; access controls per engagement.
- PII: minimized, masked, and retention-limited.
- Local AI: data stays local; cloud AI requires explicit engagement policy
  (`11` §14).

---

## 13. Incident Response

- Security incidents (sandbox escape, secret leak, unauthorized access) follow:
  detect (alerts + audit) → contain (quarantine tool/plugin/user, revoke
  tokens) → eradicate (patch, rotate) → recover → lessons learned (ratify changes).
- Incident channel: `SECURITY.md` reporting path; PGP for sensitive reports.

---

## 14. Compliance Mappings (reference)

- OWASP ASVS (L2) for the platform's own web surface.
- OWASP Top 10 for findings taxonomy.
- NIST/ISO 27001 controls for audit and secrets management (enterprise edition).
- SOC 2 control mapping (enterprise).

---

## 15. Security Testing Requirements

Mandatory security tests in CI (`15 - Testing Standards.md` §6):

- Sandbox escape attempts (fixtures).
- Command/path/template injection via tool args and plugin input.
- Secret leakage in logs/errors/reports/AI prompts.
- Scope violation enforcement.
- RBAC bypass attempts.
- Deserialization abuse.
- Prompt-injection resilience.
- Supply chain (dependency scan, plugin signature checks).

---

## 16. References

- `05 - Plugin SDK Specification.md` §13 (plugin security)
- `06 - Tool Adapter SDK.md` §12 (adapter safety contract)
- `11 - AI Standards.md` §12 (AI safety)
- `15 - Testing Standards.md` §6 (security tests)
- `20 - REST API Standards.md` §Security
