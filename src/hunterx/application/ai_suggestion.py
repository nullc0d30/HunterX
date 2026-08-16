# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI action-suggestion producer for the mission decision loop.

The AI is an **advisory** decision source: it proposes one of the already
available candidate actions (a capability the deterministic planner can also
rank) plus a short rationale. It never picks a tool, never executes anything,
and never bypasses policy, scope, budgets, sandbox enforcement or stop
conditions. The deterministic :class:`MissionDecisionEngine` remains the final
authority — it recomputes the ranking and only marks the decision
``ai_assisted`` when the AI suggestion coincides with the deterministically
selected action.

Every failure path (client unavailable, provider error, timeout, malformed or
unparseable response, invalid or out-of-candidate suggestion) degrades to a
"no suggestion" result so the mission continues deterministically.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from hunterx.domain.ports.services import AIPort


@dataclass(frozen=True, slots=True)
class AISuggestion:
    """A validated advisory action suggestion.

    Attributes:
        action_id: a candidate action id the AI recommends (``""`` when the AI
            produced no usable suggestion).
        reason: short advisory rationale (never executed).
        invoked: whether the AI provider was actually invoked this cycle.
        latency_ms: provider round-trip time when invoked.
        error: reason the suggestion was not produced (empty on success).
        raw: the raw provider response (diagnostics only, no secrets).

    """

    action_id: str = ""
    reason: str = ""
    invoked: bool = False
    latency_ms: int = 0
    error: str = ""
    raw: str = ""

    @property
    def usable(self) -> bool:
        """Return ``True`` when the suggestion targets a valid candidate."""
        return bool(self.action_id)


class AIActionSuggester:
    """Produce a constrained, validated AI action suggestion.

    Args:
        ai: the :class:`AIPort` client (``None`` keeps AI disabled and the
            mission fully deterministic).
        model: optional model override (defaults to the provider's configured
            model when empty).

    """

    def __init__(self, ai: AIPort | None = None, *, model: str = "") -> None:
        self._ai = ai
        self._model = model

    # -- public -------------------------------------------------------------

    def suggest(
        self,
        mission: Any,
        candidates: list[Any],
    ) -> AISuggestion:
        """Return an advisory suggestion for ``mission`` given ``candidates``.

        ``candidates`` is the list of ready candidate actions (each exposing
        ``action_id``, ``capability``, ``description`` and ``tool_ids``). The
        suggestion is validated against this set; anything else is rejected.
        """
        if self._ai is None:
            return AISuggestion(error="AI client unavailable")
        if not candidates:
            return AISuggestion(error="no candidate actions to suggest")

        candidate_ids = [getattr(candidate, "action_id", "") for candidate in candidates]
        prompt = _build_prompt(mission, candidates)
        started = time.monotonic()
        try:
            response = self._ai.complete(prompt, model=self._model or None)
        except Exception as exc:  # noqa: BLE001 - AI failure must never break the mission
            latency = int((time.monotonic() - started) * 1000)
            return AISuggestion(invoked=True, latency_ms=latency, error=f"AI request failed: {exc}")
        latency = int((time.monotonic() - started) * 1000)

        parsed, error = _parse_suggestion(response)
        if parsed is None:
            return AISuggestion(invoked=True, latency_ms=latency, error=error, raw=response)

        action_id = str(parsed.get("suggested_action_id", ""))
        reason = str(parsed.get("reason", ""))
        if action_id not in candidate_ids:
            return AISuggestion(
                invoked=True,
                latency_ms=latency,
                error=(
                    f"AI suggested '{action_id}' which is not an available candidate"
                    f" (valid: {', '.join(candidate_ids)})"
                ),
                raw=response,
            )
        return AISuggestion(action_id=action_id, reason=reason, invoked=True, latency_ms=latency, raw=response)


def _build_prompt(mission: Any, candidates: list[Any]) -> str:
    """Build a constrained prompt from mission context and candidate actions.

    Only summary context is included (no database dump, no secrets). The AI is
    asked to recommend one of the listed candidate action ids.
    """
    mission_id = getattr(mission, "mission_id", "")
    objective = getattr(mission.mission, "objective", "")
    strategy = getattr(mission.policy, "strategy", "")
    mode = getattr(mission.mission, "mode", "")

    context = getattr(mission, "context", None)
    target = getattr(context, "target_id", "") if context is not None else ""
    current_phase = getattr(context, "current_phase", "") if context is not None else ""
    assets = len(getattr(context, "assets", {}) or {})
    technologies = len(getattr(context, "technologies", {}) or {})
    services = len(getattr(context, "services", {}) or {})
    endpoints = len(getattr(context, "endpoints", {}) or {})
    observations = len(getattr(context, "observations", []) or [])
    decisions = len(getattr(context, "decisions", []) or [])
    executed = [
        str(getattr(execution, "tool_id", ""))
        for execution in (getattr(context, "tool_executions", []) or [])[-8:]
    ]
    failed = [
        str(getattr(observation, "tool_id", ""))
        for observation in (getattr(context, "observations", []) or [])
        if getattr(observation, "observation_type", "") == "tool_failure"
    ][-8:]

    candidate_lines = [
        f"- {getattr(c, 'action_id', '')} | capability={getattr(c, 'capability', '')} | "
        f"desc={getattr(c, 'description', '')} | tools={','.join(getattr(c, 'tool_ids', ()) or ())}"
        for c in candidates
    ]

    prompt = (
        "You are an advisory security-assessment planner. Recommend the single most valuable "
        "NEXT action from the provided candidate list. You must pick one of the listed action ids "
        "exactly (copy it verbatim). Respond with JSON only:\n"
        '{"suggested_action_id": "<action id>", "reason": "<one short sentence>"}\n\n'
        f"Mission: {mission_id}\n"
        f"Objective: {objective}\n"
        f"Strategy: {strategy}\n"
        f"Mode: {mode}\n"
        f"Target: {target}\n"
        f"Current phase: {current_phase}\n"
        f"State: assets={assets}, technologies={technologies}, services={services}, "
        f"endpoints={endpoints}, observations={observations}, decisions={decisions}\n"
        f"Recently executed tools: {', '.join(executed) or 'none'}\n"
        f"Recently failed tools: {', '.join(failed) or 'none'}\n"
        "Available candidate actions:\n"
        + "\n".join(candidate_lines)
    )
    return prompt


def _parse_suggestion(response: str) -> tuple[dict[str, Any] | None, str]:
    """Parse the AI response into ``{"suggested_action_id", "reason"}``.

    Accepts a top-level JSON object, possibly wrapped in markdown fences or
    trailing prose. Returns ``(None, error)`` on malformed content.
    """
    text = (response or "").strip()
    if not text:
        return None, "empty AI response"
    # Strip markdown code fences if present.
    if text.startswith("```"):
        text = text.strip("`")
        text = text.removeprefix("json").strip()
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        text = text[start : end + 1]
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None, "AI response is not valid JSON"
    if not isinstance(payload, dict):
        return None, "AI response is not a JSON object"
    if not payload.get("suggested_action_id"):
        return None, "AI response is missing 'suggested_action_id'"
    return payload, ""


__all__ = ["AIActionSuggester", "AISuggestion"]
