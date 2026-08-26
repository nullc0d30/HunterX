# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI Hunt Director Implementation.

The AI Hunt Director is the autonomous decision-making authority for
security-assessment missions. Every meaningful planning cycle it receives the
complete mission state (target, scope, authorization, phase, discovered
technologies/services/endpoints/parameters, observations, negative evidence,
hypotheses, findings, attack paths, previous actions and their results,
available tools with descriptions/schemas, resource budget AND the Security
Test Matrix) and returns a structured decision:

    {
      "question": "<security question being answered>",
      "security_domain": "<matrix domain>",
      "reason": "...",
      "action": "execute_tool" | "complete",
      "capability": "<capability id>",
      "tool": "<tool hint or empty for auto-select>",
      "arguments": {"asset": "...", ...},
      "expected_evidence": [...],
      "validation_plan": "..."
    }

HunterX (never the AI) enforces scope, authorization, safety, budgets, tool
contracts and evidence requirements through the policy gate before executing
anything.

Context is compacted to bounded summaries — never unlimited history, but
never dropping security-relevant context.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from hunterx.application.ai_hunt_director.protocol import (
    ActionType,
    AIHuntDecision,
    AIHuntDirectorError,
    HuntContext,
)
from hunterx.shared.ids import generate_id


#: Maximum items per context section (context compaction bounds).
_MAX_OBSERVATIONS = 25
_MAX_ENDPOINTS = 40
_MAX_PARAMETERS = 30
_MAX_TECH = 30
_MAX_OPEN_HYPOTHESES = 20
_MAX_SETTLED_HYPOTHESES = 10
_MAX_PREVIOUS_DECISIONS = 10
_MAX_PREVIOUS_RESULTS = 8
_MAX_NEGATIVE_EVIDENCE = 10
_MAX_ATTACK_PATHS = 10

_SYSTEM_PROMPT = """You are the AI Hunt Director of an autonomous security-testing engine.
You direct an ACTIVE security assessment of an explicitly authorized target.
Reconnaissance is only the beginning: after enough attack-surface knowledge
exists you must transition to ACTIVE security testing (injection, authz,
authn, session, business logic, client-side, misconfiguration, ...) and keep
testing until every applicable domain in the Security Test Matrix has a
terminal state.

Decision rules:
1. Think question-first: state the security QUESTION you want answered, pick
   the capability that answers it, then choose arguments.
2. Drive the Security Test Matrix: prefer domains whose status is not_assessed
   or in_progress. Never repeat a capability on the same asset when its result
   is already recorded unless you are validating a specific signal.
3. Use discoveries: when a previous tool result reveals new endpoints,
   parameters or technologies, your next decision MUST change because of it.
4. "complete" is ONLY allowed when every applicable domain in the provided
   Security Test Matrix already has a terminal status. Otherwise pick work.
5. Respond with ONE JSON object only — no prose, no markdown fences."""

_RESPONSE_SCHEMA = """{
  "question": "the security question this action answers",
  "security_domain": "one domain id from the matrix",
  "reason": "one short sentence",
  "action": "execute_tool",
  "capability": "one capability id from AVAILABLE CAPABILITIES",
  "tool": "optional preferred tool id or empty string",
  "arguments": {"asset": "the exact URL/host to test", "param": "optional parameter name"},
  "expected_evidence": ["what a positive/negative result looks like"],
  "validation_plan": "how the result will be confirmed or refuted"
}

For "action": "complete" use:
{"question": "...", "security_domain": "...", "reason": "...", "action": "complete"}"""


class AIHuntDirector:
    """LLM-driven autonomous hunt director.

    The director NEVER executes anything: it returns structured decisions that
    HunterX validates through the policy gate and executes through the normal
    capability/tool pipeline with full observation feedback.
    """

    def __init__(
        self,
        ai_port: Any = None,
        model: str = "",
        provider: str = "",
        max_tokens: int = 2048,
        temperature: float = 0.2,
        max_retries: int = 2,
        allowed_capabilities: tuple[str, ...] = (),
    ) -> None:
        self._ai = ai_port
        self._model = model
        self._provider = provider
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._max_retries = max(1, max_retries)
        self._allowed_capabilities = frozenset(allowed_capabilities)
        #: Cumulative attribution counters.
        self.decisions_made = 0
        self.last_error = ""

    # -- public API ----------------------------------------------------------

    @property
    def provider(self) -> str:
        return self._provider

    @property
    def model(self) -> str:
        return self._model

    def decide_next_action(self, context: HuntContext) -> AIHuntDecision:
        """Ask the model for the next security-testing action."""
        if self._ai is None:
            raise AIHuntDirectorError("No AI port configured")
        prompt = self.build_prompt(context)
        last_error = ""
        for _attempt in range(self._max_retries):
            started = time.monotonic()
            try:
                response = self._ai.complete(prompt, model=self._model or None)
            except TimeoutError:
                last_error = "AI request timed out"
                continue
            except Exception as exc:  # noqa: BLE001 - retried below
                last_error = f"AI request failed: {exc}"
                continue
            latency_ms = int((time.monotonic() - started) * 1000)
            parsed, error = _parse_decision(response, context)
            if parsed is None:
                last_error = error
                continue
            self.decisions_made += 1
            return _decision_from_payload(parsed, latency_ms=latency_ms)
        self.last_error = last_error
        raise AIHuntDirectorError(f"AI Hunt Director failed: {last_error}")

    def explain_failure(self) -> str:
        return self.last_error

    # -- prompt construction ---------------------------------------------------

    def build_prompt(self, context: HuntContext) -> str:
        """Build the complete mission-state prompt (compacted)."""
        sections: list[str] = [_SYSTEM_PROMPT, "", f"## RESPONSE SCHEMA\n{_RESPONSE_SCHEMA}", ""]
        sections.append("## MISSION")
        sections.append(f"mission_id: {context.mission_id}")
        sections.append(f"objective: {context.objective}")
        sections.append(f"target: {context.target}")
        sections.append(f"current_phase: {context.current_phase}")
        sections.append(f"strategy: {context.current_strategy}")
        sections.append(f"scope: {json.dumps(context.scope, default=str)}")
        sections.append(f"authorization: {json.dumps(context.authorization_context, default=str)}")

        sections.append("\n## DISCOVERED TARGET MODEL")
        tech = context.technologies[:_MAX_TECH]
        services = context.services[:_MAX_TECH]
        endpoints = context.endpoints[:_MAX_ENDPOINTS]
        parameters = context.parameters[:_MAX_PARAMETERS]
        sections.append(f"technologies({len(context.technologies)}): {', '.join(tech) or 'none'}")
        sections.append(f"services({len(context.services)}): {', '.join(services) or 'none'}")
        if endpoints:
            sections.append(
                f"endpoints({len(context.endpoints)}, showing {len(endpoints)}):\n  " + "\n  ".join(endpoints)
            )
        else:
            sections.append("endpoints: none yet")
        sections.append(f"parameters({len(context.parameters)}): {', '.join(parameters) or 'none'}")
        surface = context.attack_surface if isinstance(context.attack_surface, dict) else {}
        if surface:
            sections.append(f"attack_surface: {json.dumps(surface, default=str)[:1200]}")

        sections.append("\n## OBSERVATIONS (most recent first)")
        obs = list(reversed(context.observations))[:_MAX_OBSERVATIONS]
        if obs:
            counts: dict[str, int] = {}
            for observation in context.observations:
                counts[observation.observation_type] = counts.get(observation.observation_type, 0) + 1
            sections.append(f"total={len(context.observations)} by_type={json.dumps(counts)}")
            for observation in obs:
                summary = observation.content_summary.replace("\n", " ")[:220]
                sections.append(f"- [{observation.observation_type}] via {observation.tool_id} @ {observation.asset_key}: {summary}")
        else:
            sections.append("none yet — begin reconnaissance")

        if context.negative_evidence:
            negative = context.negative_evidence[:_MAX_NEGATIVE_EVIDENCE]
            sections.append(f"\n## NEGATIVE EVIDENCE ({len(context.negative_evidence)} total)")
            for entry in negative:
                sections.append(f"- {json.dumps(entry, default=str)[:200]}")

        sections.append("\n## HYPOTHESES")
        open_states = {"proposed", "supported", "weakly_supported", "inconclusive", "novel_behavior"}
        open_h = [h for h in context.hypotheses if h.state.value in open_states]
        settled_h = [h for h in context.hypotheses if h.state.value not in open_states]
        sections.append(
            f"open={len(open_h)} settled={len(settled_h)}"
            f" (validated={sum(1 for h in settled_h if h.state.value == 'validated')},"
            f" refuted/disproved={sum(1 for h in settled_h if h.state.value in ('refuted', 'disproved', 'rejected'))})"
        )
        for hypothesis in sorted(open_h, key=lambda h: -h.priority)[:_MAX_OPEN_HYPOTHESES]:
            sections.append(
                f"- [{hypothesis.state.value}] p={hypothesis.priority:.2f} ({hypothesis.vulnerability_class}) {hypothesis.statement[:180]}"
            )
        for hypothesis in settled_h[:_MAX_SETTLED_HYPOTHESES]:
            sections.append(f"- [{hypothesis.state.value}] {hypothesis.statement[:140]}")

        sections.append("\n## FINDINGS & ATTACK PATHS")
        for finding in context.findings[:20]:
            sections.append(
                f"- [{finding.severity}] {finding.title} ({finding.vulnerability_class}) stage={finding.stage} conf={finding.confidence:.2f}"
            )
        if not context.findings:
            sections.append("findings: none validated yet")
        for path in context.attack_paths[:_MAX_ATTACK_PATHS]:
            sections.append(f"- path: {json.dumps(path, default=str)[:200]}")
        if not context.attack_paths:
            sections.append("attack paths: none correlated yet — evaluate chaining opportunities")

        sections.append("\n## PREVIOUS ACTIONS & RESULTS (chronological)")
        for decision in context.previous_decisions[-_MAX_PREVIOUS_DECISIONS:]:
            sections.append(f"- decided: {json.dumps(decision, default=str)[:200]}")
        for result in context.previous_tool_results[-_MAX_PREVIOUS_RESULTS:]:
            sections.append(f"- executed: {json.dumps(result, default=str)[:260]}")
        if context.pending_actions:
            sections.append(
                "\nALREADY SCHEDULED/PENDING (do NOT repeat these capability+asset pairs):\n  "
                + "\n  ".join(context.pending_actions[:40])
            )

        sections.append("\n## SECURITY TEST MATRIX (completion contract)")
        matrix = context.security_matrix or {}
        sections.append(f"summary: {json.dumps(matrix.get('summary', matrix), default=str)[:600]}")
        for domain in matrix.get("domains", []):
            if domain.get("applicability") != "applicable":
                sections.append(
                    f"- {domain['domain']}: {domain['status']} (not applicable: {str(domain.get('applicability_evidence', ''))[:80]})"
                )
                continue
            sections.append(
                f"- {domain['domain']}: {domain['status']} tests={domain.get('tests', 0)}"
                f" findings={domain.get('findings', 0)} tools={','.join(domain.get('tools_used', [])) or '-'}"
            )

        sections.append("\n## RESOURCE BUDGET")
        state = context.resource_state
        sections.append(
            f"executions_remaining={state.execution_remaining} time_remaining_s={state.time_remaining}"
            f" concurrency={state.concurrent_executions}/{state.max_concurrency}"
        )

        sections.append("\n## AVAILABLE CAPABILITIES (choose capability ids from THIS list)")
        for cap in context.available_capabilities:
            schema = json.dumps(cap.input_schema, default=str)[:200] if cap.input_schema else ""
            preconditions = "; ".join(cap.preconditions)[:120]
            sections.append(
                f"- {cap.tool_id}: {cap.description[:160]}"
                + (f" | args-hint: {schema}" if schema else "")
                + (f" | requires: {preconditions}" if preconditions else "")
            )
        if context.available_tools:
            extra = [t for t in context.available_tools if t not in {c.tool_id for c in context.available_capabilities}]
            if extra:
                sections.append(f"additional tool ids: {', '.join(extra[:60])}")
        if context.coverage_matrix:
            sections.append(f"\n## COVERAGE MATRIX\n{json.dumps(context.coverage_matrix, default=str)[:800]}")

        sections.append(
            "\nRespond with ONE JSON object following RESPONSE SCHEMA. Choose security_domain from the matrix; "
            "choose capability from AVAILABLE CAPABILITIES. If the matrix still lists non-terminal applicable "
            "domains, action MUST be \"execute_tool\"."
        )
        return "\n".join(sections)


_VALID_ACTIONS = {"execute_tool", "complete", "reassess"}


def _extract_json(text: str) -> dict[str, Any] | None:
    """Extract the outermost JSON object from a model reply (fence-tolerant)."""
    if not text or not text.strip():
        return None
    cleaned = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if fenced:
        cleaned = fenced.group(1)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start < 0 or end <= start:
        return None
    candidate = cleaned[start : end + 1]
    try:
        payload = json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _parse_decision(response: str, context: HuntContext) -> tuple[dict[str, Any] | None, str]:
    """Validate and normalize a raw model reply into a decision payload."""
    payload = _extract_json(response)
    if payload is None:
        return None, "AI response contained no parsable JSON object"
    action = str(payload.get("action", "execute_tool")).strip().lower()
    if action not in _VALID_ACTIONS:
        return None, f"unknown action '{action}'"
    capability = str(payload.get("capability", "")).strip().lower().replace("-", "_").replace(" ", "_")
    if action == "execute_tool":
        known = {c.tool_id.lower() for c in context.available_capabilities}
        if not capability:
            return None, "missing 'capability' for execute_tool action"
        if capability not in known and not any(k in capability for k in ("scan", "discovery", "analysis", "fingerprint")):
            return None, f"capability '{capability}' is not in the available capability list"
    # For "complete" action: do NOT check matrix completeness here.
    # That check is done at a higher level (_request_ai_decision) which can
    # properly fall back to the deterministic planner. Treating an incomplete
    # matrix as a parsing failure triggers unwanted retries that consume the
    # next scripted AI response.
    return payload, ""


def _decision_from_payload(payload: dict[str, Any], *, latency_ms: int = 0) -> AIHuntDecision:
    """Build the structured AIHuntDecision from a validated payload."""
    action_raw = str(payload.get("action", "execute_tool")).strip().lower()
    action_map = {
        "execute_tool": ActionType.EXECUTE_TOOL,
        "complete": ActionType.COMPLETE,
        "reassess": ActionType.REASSESS,
    }
    action_type = action_map[action_raw]
    reason = str(payload.get("reason", ""))
    arguments = payload.get("arguments") if isinstance(payload.get("arguments"), dict) else {}
    expected = payload.get("expected_evidence")
    if isinstance(expected, str):
        expected = [expected]
    try:
        priority = min(1.0, max(0.0, float(payload.get("priority", 0.7))))
    except (TypeError, ValueError):
        priority = 0.7
    return AIHuntDecision(
        decision_id=f"ai-{generate_id()}",
        action_type=action_type,
        tool_id=str(payload.get("tool", "")),
        capability=str(payload.get("capability", "")).strip().lower().replace("-", "_"),
        arguments=dict(arguments or {}),
        objective=str(payload.get("objective", "")) or str(payload.get("question", "")),
        expected_signal="; ".join(expected)[:400] if expected else "",
        evidence_required=[str(item) for item in (expected or [])][:8],
        validation_required=[str(payload.get("validation_plan", ""))][:4],
        priority=priority,
        rationale=reason,
        rationale_summary=(reason[:200] if reason else "AI hunt-director decision"),
        confidence=0.75,
        decision_type=action_type.value.upper(),
        question=str(payload.get("question", "")),
        security_domain=str(payload.get("security_domain", "")),
        validation_plan=str(payload.get("validation_plan", "")),
        metadata={
            "latency_ms": latency_ms,
            "provider_directed": True,
        },
    )


__all__ = ["AIHuntDirector"]
