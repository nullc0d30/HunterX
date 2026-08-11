# 11 — AI Standards

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** AI Engine, planner, reasoning, agents, AI usage in tools/plugins, report drafting

---

## 1. AI Role Charter

HunterX uses AI as an **intelligent operator, never an unchecked oracle**:

- AI **proposes, plans, triages, correlates, and drafts**.
- AI **never** silently executes destructive, scope-exceeding, or
  credential-mutating actions.
- Every AI decision is **recorded, versioned, and explainable** via
  `AIProvenance` (`08` §3.18).
- Deterministic systems (plan expansion, dedup, risk math) remain rule-based;
  AI augments, does not replace, determinism where reproducibility is required.

---

## 2. AI Capability Catalog

| Capability | Owner | Approval level |
|------------|-------|----------------|
| Plan generation (template expansion) | Planner | deterministic; AI only for non-deterministic branches |
| Replanning / next-action suggestion | Planner | operator for destructive |
| Hypothesis generation | ThreatModelingAgent | auto (read-only) |
| Triage & prioritization of findings | VerificationAgent | auto (no execute) |
| Correlation suggestions | Correlation Engine | auto (read-only) |
| Report drafting | Reporting Agent | auto (draft only) |
| Evidence summarization | Reporting Agent | auto |
| Tool/template selection | Planner | auto within scope |
| Payload suggestion | PayloadAgent | operator review required |
| Purple-team / detection-gap analysis | PurpleTeamAgent | auto |

---

## 3. AI Access Control

- **Provider isolation:** agents, skills, and plugins access AI **only** through
  the AI abstraction (`02` §5.2). Direct SDK imports are architecture violations.
- **Prompt gating:** prompts carry only the minimum scoped context (KG subgraph,
  finding summaries, mission scope) — never full target databases, never secrets.
- **Action gating:** the AI Engine cannot invoke tools or subprocesses. Its
  output is a *decision object* that the Workflow Engine executes through
  sandboxes and approval gates.
- **Permission gating:** `ai.invoke` is a plugin permission
  (`05` §7); unauthorized invocations are rejected at the host.

---

## 4. Prompt Engineering Standards

- **Schema-typed prompts:** every prompt class has a versioned JSON Schema for
  output (`output_schema`). Free-form prompts are forbidden for decisions.
- **Context budget:** declared per call (`context_limit_tokens`); the system
  truncates/summarizes beyond budget — never silently drops security-relevant facts.
- **Masking:** secrets, credentials, cookies, tokens, and PII are masked before
  prompt assembly and verified after (`masking` module).
- **Grounding:** where available, prompts include grounded reference material
  (tool knowledge, CVE/CWE text, evidence snippets) with citations.
- **Anti-hallucination:** prompts instruct *"answer only from provided
  evidence; if unknown, state UNKNOWN"* and enforce it in validation.

---

## 5. Decision-Making & Reasoning Model

The platform uses a **4-stage investigative reasoning loop**
(consistent with the v6 architecture):

```
OBSERVE      → gather passive/active evidence (no AI required)
HYPOTHESIZE  → AI generates candidate hypotheses from evidence
PROBE        → deterministic tools/skills test each hypothesis
VERIFY       → evidence cross-validation + confidence scoring
```

Each stage is recorded. The loop is iterative: verified hypotheses feed the
next observation cycle. Reasoning is:
- **Evidence-first:** hypotheses without evidence are discarded or flagged.
- **Chained:** outputs of one stage are inputs to the next (stateful, per-mission).
- **Auditable:** full chain is replayable from `AIProvenance`.

---

## 6. Validation of AI Output

Every AI result passes the pipeline
(`02` §6.3) before being consumed:

1. **Schema validation** — output conforms to prompt's JSON Schema; else reject.
2. **Type/range validation** — enums, score ranges (0..1), ID formats.
3. **Consensus validation** — N-sample aggregation (strict unanimous /
   relaxed majority) configurable per call class.
4. **Grounding check** — claims reference available evidence; unsupported
   claims flagged `UNSUPPORTED`.
5. **Safety check** — no destructive action requested without approval; no
   scope or credential mutation.

Invalid output → retry (bounded) → fallback strategy (degrade) → failure with
reason recorded.

---

## 7. Confidence Scoring

- `confidence ∈ [0,1]` assigned by `ConfidenceScorer`.
- Components: agreement (multi-sample), schema adherence, grounding support,
  calibration priors (per capability).
- Calibration: the platform tracks **predicted confidence vs observed
  validation outcome** per capability and recalibrates (see §10 Learning).
- Confidence is stored with every decision and used by triage/reporting.

| Confidence | Meaning |
|-----------|---------|
| 0.0–0.3 | exploratory, may discard |
| 0.4–0.6 | plausible, needs probe |
| 0.7–0.8 | well-supported |
| 0.9–1.0 | verified by evidence/consensus |

---

## 8. Risk Scoring

Risk is computed by the **deterministic risk model** (mission-profile specific),
not by the LLM. AI may *suggest* adjustments, but:

- Final risk = deterministic formula (see `12 - Mission Profiles.md` §Risk).
- Human/AI overrides are stored with `{reason, by}` and never silently applied.
- AI risk suggestions are logged as advisory only.

---

## 9. Correlation

- AI assists correlation by proposing links between findings (e.g., "XSS on
  `/login` likely same parameter class as `id` endpoint").
- Proposed links require **evidence** (shared parameter, shared payload, shared
  CVE) to become graph edges; evidence-free suggestions are advisory.
- Correlation output feeds `CORRELATES_WITH` edges (`09` §10) and attack-path
  reconstruction; the graph is always SQL-truth-anchored.

---

## 10. Learning & Memory

- **Feedback loop:** validation outcomes (CONFIRMED/REFUTED) update
  per-capability calibration and tool/payload feedback scores.
- **Scoped memory:** per-agent memory with TTL/LRU (`02` §5.7/agents); memory
  is engagement-scoped and never crosses tenants.
- **No cross-mission bleeding:** learning stats may aggregate globally only as
  de-identified calibration priors; raw findings never shared across engagements.
- **Opt-out:** operators can disable learning; deterministic behavior must be
  preserved.
- **Forgetting policy:** calibration decays; old priors weighted down.

---

## 11. Optimization

- **Provider routing:** select model/provider by task class, latency, cost,
  and policy (e.g., local model for sensitive engagements).
- **Caching:** exact + semantic cache for repeated prompts (keyed, versioned).
- **Batching & async:** AI calls are batched where semantics allow; responses
  streamed for long tasks.
- **Budget control:** per-engagement token/cost budgets; hard stop with
  operator alert when exhausted.
- **Fallback chains:** preferred → fallback → local → rule-based degrade.

---

## 12. Safety & Abuse Prevention

- **No self-modification:** AI cannot alter its own prompts/versions at runtime.
- **No credential use:** AI never receives or emits credentials.
- **Prompt injection defense:** tool/network output is treated as **data**, never
  as instructions; instructions and data are delimited and validated.
- **Rate limits & quotas:** per operator, per capability, per provider.
- **Audit:** every AI call logged (prompt hash, model, provider, latency, cost,
  outcome) with `correlation_id`.
- **Incident path:** flagged outputs (UNSUPPORTED, unsafe suggestions) are
  quarantined to a review queue.

---

## 13. Reproducibility

- Every mission pins `ai_seed` and model/provider selection (config).
- Replay of a mission with the same seed + same provider + same evidence
  reproduces the same decisions (documented provider nondeterminism accepted
  and logged).
- Deterministic fallback path exists for every AI decision
  (rule-based plan expansion, severity mapping, dedup).

---

## 14. Model & Provider Governance

- Provider registry (`02` §5.2) validates capabilities before activation:
  schema conformance, latency SLA, cost, data-residency policy (local vs cloud).
- **Data residency:** sensitive engagements default to local/self-hosted models;
  cloud use requires explicit engagement setting.
- Version pinning: models referenced by exact version; upgrades are explicit
  config changes with A/B comparison in staging.

---

## 15. Metrics & Telemetry

| Metric | Type |
|--------|------|
| `hx_ai_calls_total` (by capability, provider, outcome) | counter |
| `hx_ai_latency_seconds` | histogram |
| `hx_ai_cost_total` | counter |
| `hx_ai_confidence_calibration_error` | gauge |
| `hx_ai_cache_hit_ratio` | gauge |
| `hx_ai_rejected_outputs_total` | counter |
| `hx_ai_fallback_activations_total` | counter |

All correlated with traces (`18 - Logging Standards.md`).

---

## 16. References

- `02 - Architecture.md` §5.2 (AI Engine) & §5.5 (Planner)
- `08 - Unified Security Schema.md` §3.18 (AIProvenance)
- `13 - Security Standards.md` (secrets & data handling)
- `15 - Testing Standards.md` (AI test harness & golden sets)
