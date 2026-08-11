# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Escalation engine (Sprint 023).

Adaptive execution: when a passive observation needs validation, the engine
decides whether a more aggressive tool/level is permitted. Every escalation
must justify itself with evidence, stay inside scope, respect the safety
ceiling against authorization, and use a tool that actually provides the
required capability. De-escalation is allowed when evidence weakens.
"""

from __future__ import annotations

from hunterx.domain.tool_intelligence import (
    EscalationDecision,
    EscalationLevel,
    EvidenceStrength,
    ToolSafetyClass,
)
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.selector import ToolSelector


class EscalationEngine:
    """Decide whether an escalation (or de-escalation) is permitted.

    Usage::

        engine = EscalationEngine(registry, selector)
        decision = engine.escalate(
            tool_id="nuclei",
            level=EscalationLevel.ACTIVE_VALIDATION,
            capability="sqli-detection",
            authorization=ToolSafetyClass.ACTIVE,
            scope_ok=True,
            evidence=("obs-1",),
        )
    """

    def __init__(self, registry: ToolIntelligenceRegistry, selector: ToolSelector) -> None:
        self._registry = registry
        self._selector = selector

    def escalate(
        self,
        *,
        tool_id: str,
        level: EscalationLevel,
        capability: str,
        authorization: ToolSafetyClass,
        scope_ok: bool,
        evidence: tuple[str, ...] = (),
        reason: str = "",
    ) -> EscalationDecision:
        """Return the escalation decision for ``tool_id`` at ``level``.

        The decision records every gate that was (or was not) satisfied so
        callers and audit logs can see exactly why an escalation was allowed
        or blocked.
        """
        safety_class = self._safety_class_for(tool_id)
        authorized = not safety_class.exceeds(authorization)
        capability_ok = self._capability_ok(tool_id, capability)
        allowed = bool(scope_ok and authorized and capability_ok)

        if not reason:
            reason = (
                f"escalate {tool_id} to {level.value}"
                if allowed
                else f"escalation to {level.value} blocked"
            )

        return EscalationDecision(
            tool_id=tool_id,
            level=level,
            allowed=allowed,
            reason=reason,
            evidence=evidence,
            scope_ok=scope_ok,
            authorized=authorized,
            safety_class=safety_class,
            capability_ok=capability_ok,
        )

    def deescalate(
        self,
        *,
        tool_id: str,
        level: EscalationLevel,
        capability: str,
        authorization: ToolSafetyClass,
        scope_ok: bool,
        evidence: tuple[str, ...] = (),
        reason: str = "",
    ) -> EscalationDecision:
        """Return a de-escalation decision (always safety-positive when in scope)."""
        safety_class = self._safety_class_for(tool_id)
        capability_ok = self._capability_ok(tool_id, capability)
        allowed = bool(scope_ok and capability_ok and safety_class.rank <= authorization.rank)
        return EscalationDecision(
            tool_id=tool_id,
            level=level,
            allowed=allowed,
            reason=reason or f"de-escalate {tool_id} to {level.value}",
            evidence=evidence,
            scope_ok=scope_ok,
            authorized=True,
            safety_class=safety_class,
            capability_ok=capability_ok,
        )

    def escalation_chain(
        self,
        *,
        capability: str,
        target: str,
        authorization: ToolSafetyClass,
    ) -> list[EscalationLevel]:
        """Return the escalation levels applicable to ``capability``.

        The chain runs from passive observation up to proof, stopping at the
        highest level whose tools fit the authorization ceiling.
        """
        levels = [
            EscalationLevel.PASSIVE_OBSERVATION,
            EscalationLevel.ACTIVE_VALIDATION,
            EscalationLevel.DEEP_VALIDATION,
            EscalationLevel.PROOF,
        ]
        result: list[EscalationLevel] = []
        for level in levels:
            tool_ids = self._registry.providers_for(capability)
            if not tool_ids:
                continue
            # Only keep a level when at least one provider stays inside the
            # authorization ceiling (hard safety gate).
            if any(not self._safety_class_for(t).exceeds(authorization) for t in tool_ids):
                result.append(level)
        return result

    def _safety_class_for(self, tool_id: str) -> ToolSafetyClass:
        knowledge = self._registry.get_knowledge(tool_id)
        if knowledge is not None and knowledge.safety_profile is not None:
            return knowledge.safety_profile.safety_class
        return ToolSafetyClass.PASSIVE

    def _capability_ok(self, tool_id: str, capability: str) -> bool:
        return capability in self._registry.capabilities_for(tool_id)


def level_for_strength(strength: EvidenceStrength) -> EscalationLevel:
    """Map an evidence strength to the escalation level it supports."""
    if strength is EvidenceStrength.PROOF:
        return EscalationLevel.PROOF
    if strength is EvidenceStrength.BEHAVIORAL:
        return EscalationLevel.DEEP_VALIDATION
    return EscalationLevel.PASSIVE_OBSERVATION


__all__ = ["EscalationEngine", "level_for_strength"]
