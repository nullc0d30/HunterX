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

import dataclasses
import json
import random
import time
from dataclasses import dataclass
from typing import Any

from hunterx.domain.ports.services import AIPort


def _classify_ai_error(exc: Exception) -> tuple[int | None, bool]:
    """Classify a provider exception into ``(http_status, timeout)``.

    Derives the HTTP status from well-known provider error types/attributes so
    telemetry can distinguish ``429`` (rate limit), timeouts and other provider
    errors. ``None`` status means the error is not HTTP-classifiable.
    """
    status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = None
    if status in (429, 401, 402, 403, 404, 408, 413, 500, 502, 503, 504):
        return status, False
    name = f"{type(exc).__name__} {exc}".lower()
    if any(marker in name for marker in ("429", "rate limit", "too many requests")):
        return 429, False
    if any(marker in name for marker in ("timeout", "timed out")):
        return None, True
    return status, False


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
        http_status: HTTP status returned by the provider (``None`` unknown).
        timeout: ``True`` when the provider call timed out.
        fallback: ``True`` when a deterministic fallback decision was used
            instead of an AI-assisted one (rate limited / failed / skipped).
        cooldown: ``True`` when the provider was skipped due to an active
            rate-limit cooldown.
        deterministic: ``True`` when the decision was made without AI reasoning
            (cooldown, single candidate, free-tier throttle).

    """

    action_id: str = ""
    reason: str = ""
    invoked: bool = False
    latency_ms: int = 0
    error: str = ""
    raw: str = ""
    http_status: int | None = None
    timeout: bool = False
    fallback: bool = False
    cooldown: bool = False
    deterministic: bool = False

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
        provider: provider name for telemetry.
        min_interval_s: minimum wall-clock gap between AI calls (free-tier
            request budget — trivial decisions do not need the model every
            cycle).
        backoff_s: base cooldown applied after a 429.
        max_cooldown_s: ceiling for the 429 cooldown.

    Free-tier resilience: a ``429`` (or any provider failure) puts the provider
    into a shared cooldown (honoring ``Retry-After`` when supplied, otherwise
    bounded exponential backoff with jitter). During cooldown the suggester
    returns a deterministic (non-AI) result so the mission continues; telemetry
    records the cooldown/fallback so an incomplete assessment is never reported
    as AI-completed.

    """

    def __init__(
        self,
        ai: AIPort | None = None,
        *,
        model: str = "",
        provider: str = "",
        min_interval_s: float = 1.0,
        backoff_s: float = 5.0,
        max_cooldown_s: float = 60.0,
    ) -> None:
        self._ai = ai
        self._model = model
        self._provider = provider
        self._min_interval = max(0.0, min_interval_s)
        self._backoff = max(1.0, backoff_s)
        self._max_cooldown = max(self._backoff, max_cooldown_s)
        #: Shared per-provider/model rate-limit state (this instance is a
        #: platform singleton, so cooldown is shared across all workers).
        self._cooldown_until = 0.0
        self._last_attempt_at = 0.0
        #: Telemetry counters (aggregate across the mission).
        self._cooldown_events = 0
        self._fallback_decisions = 0
        self._deterministic_decisions = 0

    # -- state ------------------------------------------------------------------

    def rate_limited(self) -> bool:
        """Return ``True`` while the provider is in a rate-limit cooldown."""
        return time.monotonic() < self._cooldown_until

    def cooldown_remaining_s(self) -> float:
        """Return the remaining cooldown (``0`` when not rate limited)."""
        return max(0.0, self._cooldown_until - time.monotonic())

    def counters(self) -> dict[str, int]:
        """Return cumulative telemetry counters (JSON-safe)."""
        return {
            "ai_cooldown_events": self._cooldown_events,
            "ai_fallback_decisions": self._fallback_decisions,
            "ai_deterministic_decisions": self._deterministic_decisions,
        }

    def reset_rate_limit(self) -> None:
        """Clear the rate-limit cooldown (e.g. for tests / operator action)."""
        self._cooldown_until = 0.0

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

        Free-tier policy: AI is only consulted when there is more than one
        candidate (a single candidate is deterministic) and when the provider
        is not in cooldown and the per-cycle request budget allows it. Any
        failure/cooldown returns a ``fallback``/``deterministic`` suggestion so
        the mission continues with the deterministic planner — an AI failure
        never stops or falsely completes a mission.
        """
        if self._ai is None:
            return AISuggestion(error="AI client unavailable", deterministic=True)
        if not candidates:
            return AISuggestion(error="no candidate actions to suggest", deterministic=True)

        now = time.monotonic()

        if now < self._cooldown_until:
            # Rate-limited: do NOT re-fire at the provider (prevents 429 storms
            # and respects a shared cooldown). Deterministic fallback continues
            # the mission.
            self._deterministic_decisions += 1
            self._fallback_decisions += 1
            remaining = int(self.cooldown_remaining_s())
            return AISuggestion(
                error=f"AI rate-limited; deterministic fallback for {remaining}s",
                http_status=429,
                fallback=True,
                cooldown=True,
                deterministic=True,
            )

        if now - self._last_attempt_at < self._min_interval:
            # Free-tier request budget: don't ask the model for every trivial
            # decision; the deterministic planner handles this cycle.
            self._deterministic_decisions += 1
            return AISuggestion(error="AI request throttled (free-tier budget); deterministic decision", deterministic=True)

        self._last_attempt_at = now
        candidate_ids = [getattr(candidate, "action_id", "") for candidate in candidates]
        prompt = _build_prompt(mission, candidates)
        started = time.monotonic()
        http_status: int | None = None
        timeout = False
        try:
            response = self._ai.complete(prompt, model=self._model or None)
        except TimeoutError:
            latency = int((time.monotonic() - started) * 1000)
            self._fallback_decisions += 1
            return AISuggestion(
                invoked=True,
                latency_ms=latency,
                error="AI request timed out; deterministic fallback",
                timeout=True,
                fallback=True,
            )
        except Exception as exc:  # noqa: BLE001 - AI failure must never break the mission
            latency = int((time.monotonic() - started) * 1000)
            http_status, timeout = _classify_ai_error(exc)
            if http_status == 429:
                self._enter_cooldown(exc)
                return AISuggestion(
                    invoked=True,
                    latency_ms=latency,
                    error=f"AI rate limited (HTTP 429); deterministic fallback for {self.cooldown_remaining_s():.0f}s",
                    http_status=429,
                    fallback=True,
                    cooldown=True,
                    deterministic=True,
                )
            if http_status in (401, 403):
                # Authentication failure: disable AI for the mission rather than
                # hammering the endpoint with a bad key.
                self._enter_cooldown(exc, auth_failure=True)
            self._fallback_decisions += 1
            return AISuggestion(
                invoked=True,
                latency_ms=latency,
                error=f"AI request failed: {exc}; deterministic fallback",
                http_status=http_status,
                timeout=timeout,
                fallback=True,
            )
        latency = int((time.monotonic() - started) * 1000)

        parsed, error = _parse_suggestion(response)
        if parsed is None:
            self._fallback_decisions += 1
            return AISuggestion(
                invoked=True,
                latency_ms=latency,
                error=f"{error}; deterministic fallback",
                raw=response,
                http_status=http_status,
                fallback=True,
            )
        suggestion = AISuggestion(invoked=True, latency_ms=latency, raw=response, http_status=http_status)
        action_id = str(parsed.get("suggested_action_id", ""))
        reason = str(parsed.get("reason", ""))
        if action_id not in candidate_ids:
            self._fallback_decisions += 1
            return dataclasses.replace(
                suggestion,
                error=(
                    f"AI suggested '{action_id}' which is not an available candidate"
                    f" (valid: {', '.join(candidate_ids)}); deterministic fallback"
                ),
                fallback=True,
            )
        return dataclasses.replace(suggestion, action_id=action_id, reason=reason)

    # -- rate limiting ---------------------------------------------------------

    def _enter_cooldown(self, exc: Exception, *, auth_failure: bool = False) -> None:
        """Enter (or extend) the shared rate-limit cooldown with backoff + jitter.

        Honors ``Retry-After`` when the provider attached it; otherwise applies
        bounded exponential backoff with jitter. The cooldown is shared across
        all planner workers (this is the platform singleton) so a burst of 429s
        cannot amplify into more requests.
        """
        retry_after = float(getattr(exc, "retry_after", 0.0) or 0.0)
        if retry_after > 0:
            cooldown = retry_after
        else:
            backoff = self._backoff * (2 ** self._cooldown_events)
            cooldown = backoff + random.uniform(0.0, min(5.0, backoff))
        cooldown = min(cooldown, self._max_cooldown)
        if auth_failure:
            # An auth failure disables AI for a long window (don't hammer).
            cooldown = max(cooldown, self._max_cooldown)
        self._cooldown_events += 1
        self._cooldown_until = max(self._cooldown_until, time.monotonic() + cooldown)


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
