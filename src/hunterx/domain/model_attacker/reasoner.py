# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Model-agnostic reasoner for the autonomous attack loop.

The reasoner is the *only* place the connected model is invoked. It builds a
structured reasoning context (target, capability catalog, discovered surfaces,
previous observations, contradictions, findings, adjacent paths), calls the
configured :class:`AIPort`, parses the JSON hypothesis output and validates
every field against the real catalog and scope. Model output that fails
validation is rejected and recorded — never fabricated and never silently
treated as exhaustion. Retries bounded by ``attempts``; a persistent failure is
reported as ``MODEL_UNAVAILABLE``/``RESOURCE_LIMIT``, not completion.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any

from hunterx.domain.model_attacker.enums import ModelFailureReason
from hunterx.domain.model_attacker.models import ModelHypothesis
from hunterx.domain.ports.services import AIPort
from hunterx.domain.vulnerability_capability.registry import is_vulnerability_class

#: Recognised differential signal vocabulary (class-specific analysis results).
_KNOWN_SIGNALS = {
    "none",
    "error_based",
    "error-based",
    "boolean",
    "reflected",
    "reflection",
    "out_of_band",
    "time_based",
    "time-based",
    "content",
    "status",
    "redirect",
    "header",
    "exposed",
}

_MAX_REASONING = 240
_MAX_STRATEGY = 80


@dataclass(frozen=True, slots=True)
class ReasonResult:
    """The outcome of one model reasoning round."""

    hypotheses: tuple[ModelHypothesis, ...] = ()
    rejected: tuple[dict[str, Any], ...] = ()
    invoked: bool = False
    latency_ms: int = 0
    error: str = ""
    failure_reason: ModelFailureReason = ModelFailureReason.NONE
    raw: str = ""

    @property
    def usable(self) -> bool:
        """Return ``True`` when the model produced at least one hypothesis."""
        return bool(self.hypotheses)


class ModelReasoner:
    """Invoke the configured model and return validated attack hypotheses.

    Args:
        ai: the :class:`AIPort` client (model-agnostic; ``None`` keeps the
            attacker deterministic without a model).
        model: optional model override (defaults to the provider's configured
            model when empty).
        attempts: bounded retry count for malformed/transient model output.
        timeout_s: optional provider timeout (passed through to ``complete``).

    """

    def __init__(self, ai: AIPort | None = None, *, model: str = "", attempts: int = 2, timeout_s: float = 90.0) -> None:
        self._ai = ai
        self._model = model
        self._attempts = max(1, attempts)
        self._timeout_s = timeout_s

    @property
    def available(self) -> bool:
        """Return ``True`` when a model is wired and usable."""
        return self._ai is not None

    def reason(self, context: dict[str, Any]) -> ReasonResult:
        """Ask the model for hypotheses over ``context``.

        Every candidate is validated against the real capability catalog and
        the target scope. Invalid candidates are recorded as rejected with a
        reason; the mission is never marked exhausted because the model failed.
        """
        if self._ai is None:
            return ReasonResult(error="no model connected", failure_reason=ModelFailureReason.UNAVAILABLE)
        prompt = build_prompt(context)
        last_error = ""
        last_raw = ""
        for _ in range(self._attempts):
            started = time.monotonic()
            try:
                response = self._ai.complete(prompt, model=self._model or None)
            except Exception as exc:  # noqa: BLE001 - provider failures are bounded and reported
                last_error = f"model request failed: {exc}"
                last_raw = ""
                continue
            latency = int((time.monotonic() - started) * 1000)
            hypotheses, rejected_or_error = _parse_hypotheses(response, context)
            if hypotheses is not None:
                return ReasonResult(hypotheses=hypotheses, rejected=rejected_or_error, invoked=True, latency_ms=latency, raw=response)
            last_error = rejected_or_error or "malformed model output"
            last_raw = response
        return ReasonResult(invoked=True, error=last_error, failure_reason=_failure_reason(last_error), raw=last_raw)


def _failure_reason(error: str) -> ModelFailureReason:
    lowered = str(error or "").lower()
    if "timeout" in lowered:
        return ModelFailureReason.TIMEOUT
    if "rate" in lowered or "limit" in lowered or "429" in lowered:
        return ModelFailureReason.PROVIDER_LIMIT
    if "invalid" in lowered or "malformed" in lowered or "unexpected" in lowered:
        return ModelFailureReason.INVALID_OUTPUT
    return ModelFailureReason.UNAVAILABLE


def build_prompt(context: dict[str, Any]) -> str:
    """Build the JSON-only reasoning prompt from the structured context."""
    surface_lines = "\n".join(
        f"- surface={item.get('surface')} parameters={','.join(str(p) for p in item.get('parameters') or [])} layer={item.get('layer')}"
        for item in context.get("surfaces", [])
    ) or "  (none discovered yet)"
    catalog_lines = ", ".join(context.get("catalog", []) or []) or "(empty)"
    previous = context.get("observations", [])
    observation_lines = "\n".join(
        f"- {item.get('capability')} on {item.get('surface')} vector={item.get('attack_vector')} signal={item.get('signal')} supported={item.get('supported')}"
        for item in previous
    ) or "  (none)"
    finding_lines = "\n".join(
        f"- {item.get('vulnerability_class')} on {item.get('surface')} vector={item.get('vector')} severity={item.get('severity')}"
        for item in context.get("findings", [])
    ) or "  (none)"
    adjacent_lines = "\n".join(
        f"- capability={item.get('capability')} surface={item.get('surface')} vector={item.get('attack_vector')} ({item.get('reason', '')})"
        for item in context.get("adjacent_paths", [])
    ) or "  (none)"
    disproven = ", ".join(context.get("disproven", []) or []) or "(none)"
    return (
        "You are the attack-reasoning engine of an autonomous security assessment platform.\n"
        "You generate targeted attack hypotheses that HunterX will execute with real probes.\n"
        "Choose capabilities ONLY from the provided catalog and surfaces ONLY from the provided surfaces.\n"
        "Do not repeat a hypothesis whose fingerprint appears in disproven.\n"
        "Prefer adjacent paths and evidence-backed chaining over broad guessing.\n\n"
        f"TARGET: {context.get('target', '')}\n"
        f"AUTHENTICATION CONTEXT: {context.get('session_state', 'anonymous')}\n"
        f"CAPABILITY CATALOG: {catalog_lines}\n\n"
        f"DISCOVERED SURFACES:\n{surface_lines}\n\n"
        f"PREVIOUS ATTACK OBSERVATIONS:\n{observation_lines}\n\n"
        f"VALIDATED FINDINGS:\n{finding_lines}\n\n"
        f"ADJACENT ATTACK PATHS:\n{adjacent_lines}\n\n"
        f"DISPROVEN HYPOTHESES (do not re-run): {disproven}\n\n"
        "Respond with JSON ONLY, exactly this shape:\n"
        '{"hypotheses":[{"capability":"<catalog id>","surface":"<surface url>",'
        '"attack_vector":"<parameter name>","attack_strategy":"<strategy>",'
        '"expected_signal":"<error_based|reflected|boolean|content|status|time_based|out_of_band|header>",'
        '"priority":0.0,"confidence":0.0,"reasoning_context":"<short rationale>",'
        '"authentication_context":"anonymous|authenticated","parent_hypothesis":"<hypothesis_id or empty>"}]}\n'
        "If no further attack path remains, respond with {\"hypotheses\":[]}."
    )


def _parse_hypotheses(response: str, context: dict[str, Any]) -> tuple[tuple[ModelHypothesis, ...], tuple[dict[str, Any], ...]] | tuple[None, str]:
    """Parse and validate the model's JSON hypothesis output."""
    payload = _extract_json(response)
    if payload is None:
        return None, "model output is not valid JSON"
    raw_hypotheses = payload.get("hypotheses")
    if not isinstance(raw_hypotheses, list):
        return None, "model output has no 'hypotheses' list"
    surfaces = {(item.get("surface") or "") for item in context.get("surfaces", [])}
    catalog = {item.get("capability") or "" for item in context.get("surfaces", [])}
    catalog.update(str(item) for item in context.get("catalog", []) or [])
    accepted: list[ModelHypothesis] = []
    rejected: list[dict[str, Any]] = []
    for item in raw_hypotheses:
        if not isinstance(item, dict):
            rejected.append({"reason": "hypothesis is not a mapping", "raw": item})
            continue
        capability = str(item.get("capability") or "").strip()
        surface = str(item.get("surface") or "").strip()
        vector = str(item.get("attack_vector") or "").strip()
        if not is_vulnerability_class(capability):
            rejected.append({"capability": capability, "reason": "capability is not in the vulnerability catalog"})
            continue
        if surface not in surfaces:
            rejected.append({"capability": capability, "surface": surface, "reason": "surface was not discovered (out of scope)"})
            continue
        if not vector:
            rejected.append({"capability": capability, "surface": surface, "reason": "attack_vector is empty"})
            continue
        priority = _bounded_float(item.get("priority"), 0.5)
        confidence = _bounded_float(item.get("confidence"), 0.5)
        expected_signal = str(item.get("expected_signal") or "").strip().lower()
        if expected_signal and expected_signal not in _KNOWN_SIGNALS:
            expected_signal = "content"
        accepted.append(
            ModelHypothesis(
                capability=capability,
                surface=surface,
                attack_vector=vector,
                attack_strategy=str(item.get("attack_strategy") or "")[: _MAX_STRATEGY],
                reasoning_context=str(item.get("reasoning_context") or "")[: _MAX_REASONING],
                expected_signal=expected_signal,
                priority=priority,
                confidence=confidence,
                authentication_context=str(item.get("authentication_context") or "anonymous"),
                workflow_context=str(item.get("workflow_context") or ""),
                parent_hypothesis=str(item.get("parent_hypothesis") or ""),
            )
        )
    return tuple(accepted), tuple(rejected)


def _extract_json(response: str) -> dict[str, Any] | None:
    """Extract the JSON object from a model response (code fences tolerated)."""
    text = str(response or "").strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced.group(1).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        payload = json.loads(text[start : end + 1])
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _bounded_float(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, parsed))


__all__ = ["ModelReasoner", "ReasonResult", "build_prompt"]
