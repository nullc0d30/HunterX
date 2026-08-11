# 25 — Future Expansion

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** Growth strategy; guarantees of extensibility without core changes

---

## 1. Growth Mandate

The architecture MUST absorb the following growth **without modifying the Core**:

- **Unlimited tools** (target ≥ 100 integrated security tools).
- **Unlimited plugins** (target ≥ 1,000 plugins across types).
- **Distributed execution** (workers, cloud, heterogeneous hosts).
- **Multi-agent AI** (agent fleets, roles, delegation).
- **Future modules** (GUI, new assessment types, new export formats, new stores).
- **Enterprise & air-gapped deployments.**

This document defines the mechanisms that make that true and the review rules
that keep it true.

---

## 2. Why the Core Stays Stable

The Core owns only: the domain model, ports, engines, and composition.
Everything else is a plugin/adapter/knowledge-file/data artifact. Adding any of
the growth targets above is **adding data or a plugin**, not changing the core.

| Growth item | Mechanism (no core change) |
|-------------|-----------------------------|
| New tool | `tools/<id>/` package (`22`) |
| New plugin type | SDK extension point (`05`) |
| New mission type | `config/profiles/<id>.yaml` (`12`) |
| New export format | reporter plugin (`05`/`06`) |
| New AI provider | `infrastructure/ai` adapter + provider registry |
| New store backend | domain `StorePort` implementation |
| New agents | agent plugin (`05`) |
| New mission capabilities | capability registry additions |

---

## 3. Scaling Dimensions

### 3.1 Tools (100+)

- Registry + knowledge base scale by data, not code.
- Capability vocabulary is the stable contract (`22` §5); new tools map to it.
- Tool execution is horizontally scalable: workers pull tool jobs from the
  shared queue.
- Tool availability is optional: missions degrade gracefully when a tool is
  missing (`17` §7).

### 3.2 Plugins (1,000+)

- Plugin host isolates load/execution; per-plugin resource budgets.
- Marketplace scales as an external catalog (`05`).
- Plugin conflicts resolved by the dependency resolver; registry remains a
  single catalog.
- Signed/untrusted tiers keep risk bounded.

### 3.3 Distributed Execution

- Queue-backed work distribution (`02` §5.18): any worker can execute any step.
- Consumers are **idempotent**; results checkpointed (`10` §6).
- State stored centrally (TIDB); workers are stateless.
- **Cloud workers:** workers may run in cloud/kubernetes
  (deploy manifests in `deploy/helm`), registered to the same queue.
- **Heterogeneous hosts:** worker capability tags (tools installed, GPU,
  network position) let the planner route steps to capable workers.

### 3.4 Multi-Agent AI

- Agent platform (`02` §5.2 / agents) is plugin-based: new agents register
  capabilities; orchestrator/coordinator route goals.
- **Roles & delegation:** coordinator resolves conflicts; schedulers prioritize.
- **Consensus:** strict/relaxed strategies are configurable per decision class.
- **Learning:** aggregated, de-identified priors feed calibration without
  cross-tenant data (`11` §10).
- Scaling AI: provider routing + caching + token budgets (`11` §11).

### 3.5 Future Modules

Anticipated modules (implemented as plugins/modules, not core changes):

| Module | Mechanism |
|--------|-----------|
| GUI/Web UI | Consumes REST API (`20`); no core coupling |
| Data analytics / BI | Reads TIDB via read replicas + export API |
| New assessment domains (binary analysis, malware) | New mission profiles + tools (if scope amended) |
| SSO/SAML provider | `auth-provider` plugin (`05`) |
| SMS/email/chat notification | `hook` plugin |
| K8s operator / agent daemons | Deployment artifacts + API client |
| Multilingual reports | Template/i18n layer (`21` §10) |
| New compliance frameworks | Compliance mapping plugin (`21` §7) |

---

## 4. Interface Stability Commitments

- **Domain ports** are stable; implementation changes never break consumers.
- **SDK ABI** (`05`/`06`) versioned; breaking SDK changes require major SDK
  version + migration guide.
- **REST API** versioned (`/api/vN`); additive changes backward-compatible.
- **Knowledge/schema** versioned; upgrades validated before load.
- **Event taxonomy** (`18` §3) extensible by new event types without breaking
  subscribers (wildcards).

---

## 5. Guarantees Checklist (enforced in reviews)

- [ ] New feature implemented as plugin/adapter/profile — not core fork.
- [ ] No new framework/dependency imported into `domain` layer.
- [ ] No cross-subsystem internal imports (events/messages instead).
- [ ] New event/entity added to schema with minor bump + goldens.
- [ ] Scaling path identified (queue, workers, partitions) for the feature.
- [ ] Air-gap: no hard dependency on internet services at runtime (mirrors).
- [ ] Multi-tenant data isolation preserved.

---

## 6. Air-Gapped & Enterprise Deployments

- All external datasets (CVE/CWE/CAPEC/MITRE/EPSS) support offline mirrors
  (`09` §mirror, `03` `data/mirror/`).
- AI works with local models (Ollama/local) via provider abstraction
  (`11` §14).
- Telemetry: local exporters or console (`18`).
- No hard runtime dependency on a public registry/marketplace (plugins install
  from local archives).

---

## 7. Capacity Roadmap (illustrative targets)

| Horizon | Tools | Plugins | Findings | Concurrent targets | Deploy |
|---------|-------|---------|----------|--------------------|--------|
| v6.x | 40 | 150 | 10M | 500 | single + workers |
| v7.x | 75 | 400 | 100M | 2,000 | distributed + cloud workers |
| v8.x | 120 | 1,000+ | 1B | 10,000 | cloud-native, multi-region, air-gap fleet |

Each horizon revalidates: index strategy (`09`), ingest rate (`14`),
reporting scale, and audit retention.

---

## 8. Governance for Expansion

- New capabilities/schema/ADR follow `24` processes (they keep the Core stable).
- The Future Expansion Board (Architecture Owner + leads) reviews growth
  proposals quarterly.
- Backward-compatibility is a first-class requirement for every merged change.

---

## 9. References

- `02 - Architecture.md` §8 (ADRs)
- `05 - Plugin SDK Specification.md` (extension points)
- `22 - Tool Integration Standard.md` (tool growth)
- `24 - Quality Assurance.md` (change governance)
