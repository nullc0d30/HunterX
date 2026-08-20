# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive attack application service.

Phase 2. Bridges the adaptive attack domain model into mission execution:

    execution outcome → feedback classification → adaptive control state →
    bounded pacing/aggression/backoff/retry + vector selection + probe plans +
    generic workflow representation.

The service is target-agnostic: it consumes generic ``(surface, capability,
context, strategy)`` objects and only schedules the vectors that actually apply
to a discovered surface. Payload generation is delegated to HunterX's existing
vulnerability-capability engine; nothing here hardcodes a target or a tool
chain.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import Any

from hunterx.domain.adaptive_attack.control import AdaptiveRateController
from hunterx.domain.adaptive_attack.enums import (
    AggressionLevel,
    AttackState,
    AttackVector,
    FeedbackSignal,
)
from hunterx.domain.adaptive_attack.feedback import FeedbackMonitor
from hunterx.domain.adaptive_attack.probe import (
    AttackProbePlan,
    bounded_mutations,
    bounded_payloads,
    profile_for,
)
from hunterx.domain.adaptive_attack.vector import VectorSelector
from hunterx.domain.adaptive_attack.workflow import (
    AttackWorkflow,
    build_workflow_from_attributes,
)
from hunterx.domain.attack_surface.enums import SurfaceKind
from hunterx.domain.attack_surface.models import SurfaceNode
from hunterx.shared.time import utcnow_iso

#: A payload provider returns the platform's payloads for a capability over
#: surface evidence (e.g. the vulnerability-capability engine's ``build_probe``).
PayloadProvider = Callable[[str, dict[str, Any]], tuple[str, ...]]

#: Bounded fallback payloads used only when the capability engine has no probe
#: for a class (a handful of benign, well-known markers — never an unbounded
#: wordlist).
_FALLBACK_PAYLOADS: dict[str, tuple[str, ...]] = {
    "sql-injection": ("'", '"', "1 OR 1=1", "1' AND '1'='1", "1; DROP", "1 UNION SELECT NULL"),
    "nosql-injection": ('{"$gt": ""}', '{"$ne": null}', "' || true || '", "$where", "1; return true"),
    "xss": ("<script>hxprobe</script>", '"><img src=x onerror=hxprobe>', "hxprobe',alert(1),'", "{{7*7}}"),
    "ssti": ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{7*'7'}}"),
    "command-injection": (";id", "|id", "`id`", "$(id)", "& id"),
    "lfi": ("../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "/etc/passwd", "....//....//etc/passwd"),
    "xxe": ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',),
    "ssrf": ("http://127.0.0.1:80", "http://localhost/", "file:///etc/passwd", "gopher://127.0.0.1"),
    "open-redirect": ("//example.com", "https://example.com", "/\\example.com", "//evil.test"),
}


class AdaptiveAttackService:
    """Per-mission aggressive-but-bounded adaptive attack engine facade.

    Args:
        mission_id: owning mission id.
        target_key: root target key.
        controller: adaptive rate controller; ``None`` builds one.
        monitor: feedback monitor; ``None`` builds one.
        selector: vector selector; ``None`` builds one.
        payload_provider: payload source; ``None`` uses the platform capability
            engine (with a bounded fallback).
        event_bus: optional messaging port for attack events.
        enforce_pacing: whether the runner may apply the controller's pacing
            delay (tests may disable it).

    """

    def __init__(
        self,
        *,
        mission_id: str = "",
        target_key: str = "",
        controller: AdaptiveRateController | None = None,
        monitor: FeedbackMonitor | None = None,
        selector: VectorSelector | None = None,
        payload_provider: PayloadProvider | None = None,
        event_bus: Any | None = None,
        enforce_pacing: bool = True,
    ) -> None:
        self.mission_id = mission_id
        self.target_key = target_key
        self.controller = controller if controller is not None else AdaptiveRateController()
        self.monitor = monitor if monitor is not None else FeedbackMonitor()
        self.selector = selector if selector is not None else VectorSelector()
        self.payload_provider = payload_provider
        self._event_bus = event_bus
        self.enforce_pacing = enforce_pacing
        self._last_state: AttackState = self.controller.state

    # -- feedback intake ----------------------------------------------------

    def observe(
        self,
        *,
        status_code: int | None = None,
        duration_ms: int = 0,
        error: str = "",
        failure_kind: str = "",
        body_hint: str = "",
        source: str = "execution",
    ) -> FeedbackSignal:
        """Classify an execution outcome and drive the adaptive controller.

        Returns the classified signal. Every defensive response (429/403/5xx/
        timeout/connection/latency/WAF) throttles the engine — it is never
        treated as mission completion.
        """
        sample = self.monitor.observe(
            status_code=status_code,
            duration_ms=duration_ms,
            error=error,
            failure_kind=failure_kind,
            body_hint=body_hint,
            source=source,
        )
        state = self.controller.observe(sample.signal)
        if state is not self._last_state:
            self._last_state = state
            self._publish(
                "attack.state.changed",
                {
                    "mission_id": self.mission_id,
                    "state": state.value,
                    "signal": sample.signal.value,
                    **self.controller.to_dict(),
                },
            )
        return sample.signal

    def mark_blocked(self, reason: str) -> None:
        """Force the controller toward a defensive response (never completion)."""
        self.observe(status_code=403, error=f"blocked: {reason}", source="policy")
        self._publish(
            "attack.blocked",
            {"mission_id": self.mission_id, "reason": reason, "state": AttackState.BLOCKED.value},
        )

    # -- control reads ------------------------------------------------------

    def attack_state(self) -> AttackState:
        """Return the current adaptive attack state."""
        return self.controller.state

    def aggression_level(self) -> AggressionLevel:
        """Return the bounded aggression tier for the current state."""
        return self.controller.aggression_level()

    def pacing_seconds(self) -> float:
        """Return the pacing delay to apply before the next attack step."""
        return self.controller.pacing_seconds()

    def concurrency_limit(self) -> int:
        """Return the bounded concurrent attack-step ceiling."""
        return self.controller.concurrency_limit()

    def should_retry(self, signal: FeedbackSignal, *, attempts: int) -> bool:
        """Return ``True`` when a bounded strategic retry is permitted."""
        return self.controller.should_retry(signal, attempts=attempts)

    def backoff_seconds(self, attempt: int) -> float:
        """Return the capped exponential backoff for a retry attempt."""
        return self.controller.backoff_seconds(attempt)

    def is_throttling(self) -> bool:
        """Return ``True`` when the controller is throttling attack intensity."""
        return self.controller.state in (
            AttackState.THROTTLED,
            AttackState.BACKING_OFF,
            AttackState.BLOCKED,
            AttackState.RECOVERING,
        )

    # -- multi-vector planning ----------------------------------------------

    def select_vectors(self, surface: SurfaceNode) -> list[AttackVector]:
        """Return the applicable attack vectors for ``surface``."""
        return self.selector.select(surface)

    def plan_probe(
        self,
        *,
        surface: SurfaceNode,
        capability_id: str,
        payloads: tuple[str, ...] | list[str] | None = None,
        baseline_payload: str = "",
    ) -> AttackProbePlan:
        """Build a bounded attack probe plan for ``(surface, capability)``.

        The payload set is sourced from the platform capability engine (or the
        wired provider) and truncated to the current aggression tier's budget —
        escalation raises coverage, never the flood volume.
        """
        level = self.aggression_level()
        profile = profile_for(level)
        if payloads is None:
            payloads = self.payloads_for_capability(capability_id, surface)
        vectors = tuple(self.select_vectors(surface))
        evidence = self._evidence_for(surface)
        probe_spec: dict[str, Any] = {"endpoint": evidence.get("endpoint", ""), "parameter": evidence.get("parameter", "")}
        with contextlib.suppress(Exception):
            from hunterx.domain.vulnerability_capability.engine import VulnerabilityCapabilityEngine

            probe = VulnerabilityCapabilityEngine().build_probe(capability_id, evidence)
            if probe is not None:
                probe_spec = {
                    "vulnerability_class": probe.vulnerability_class,
                    "method": probe.method,
                    "parameter": probe.parameter,
                    "payload_in_header": probe.payload_in_header,
                    "body_template": probe.body_template,
                    "baseline": probe.baseline_payload,
                }
                if not baseline_payload:
                    baseline_payload = probe.baseline_payload
        mutations: tuple[dict[str, Any], ...] = self._mutations_for(surface, profile.mutation_depth)
        return AttackProbePlan(
            surface_key=surface.key,
            capability_id=capability_id,
            context=surface.context,
            vectors=vectors,
            aggression=level,
            baseline_payload=baseline_payload,
            payloads=bounded_payloads(payloads, level),
            mutations=bounded_mutations(mutations, level),
            timeout_seconds=profile.timeout_seconds,
            retry_limit=profile.retry_limit,
            probe_spec=probe_spec,
        )

    def escalate(self, plan: AttackProbePlan) -> AttackProbePlan:
        """Return the probe plan escalated one bounded tier."""
        return plan.escalated()

    def payloads_for_capability(self, capability_id: str, surface: SurfaceNode) -> tuple[str, ...]:
        """Return the platform payloads for ``capability_id`` over ``surface``.

        Delegates to the wired payload provider, then to the vulnerability
        capability engine; falls back to a small bounded marker set.
        """
        evidence = self._evidence_for(surface)
        if self.payload_provider is not None:
            with contextlib.suppress(Exception):
                payloads = self.payload_provider(capability_id, evidence)
                if payloads:
                    return tuple(payloads)
        with contextlib.suppress(Exception):
            from hunterx.domain.vulnerability_capability.engine import VulnerabilityCapabilityEngine

            probe = VulnerabilityCapabilityEngine().build_probe(capability_id, evidence)
            if probe is not None and probe.payloads:
                return tuple(probe.payloads)
        return _FALLBACK_PAYLOADS.get(capability_id, ())

    # -- workflow representation --------------------------------------------

    def workflow_for(self, surface: SurfaceNode, *, security_properties: tuple[str, ...] = ()) -> AttackWorkflow | None:
        """Build a generic :class:`AttackWorkflow` from a workflow surface.

        Returns ``None`` when the surface is not a workflow/state surface.
        """
        if surface.kind_value() not in (SurfaceKind.WORKFLOW.value, SurfaceKind.STATE_TRANSITION.value):
            return None
        attributes = surface.attributes or {}
        properties = security_properties or self._workflow_security_properties(surface)
        return build_workflow_from_attributes(
            name=surface.name,
            attributes=attributes,
            source_surface_key=surface.key,
            mission_id=self.mission_id,
            target_key=self.target_key,
            security_properties=properties,
        )

    # -- state --------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Serialize a compact adaptive-attack summary."""
        return {
            "mission_id": self.mission_id,
            "target_key": self.target_key,
            "state": self.controller.state.value,
            "aggression": self.aggression_level().value,
            "pacing_seconds": self.pacing_seconds(),
            "concurrency_limit": self.concurrency_limit(),
            "backoff_seconds": self.backoff_seconds(0),
            "is_throttling": self.is_throttling(),
            "last_signal": self.monitor.last_signal().value,
            "defensive_ratio": self.monitor.defensive_ratio(),
            "updated_at": utcnow_iso(),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full service state to a JSON-safe mapping."""
        return {
            "controller": self.controller.to_dict(),
            "monitor": self.monitor.summary(),
            "selector": self.selector.to_dict(),
            "snapshot": self.snapshot(),
        }

    # -- helpers ------------------------------------------------------------

    def _evidence_for(self, surface: SurfaceNode) -> dict[str, Any]:
        """Build capability evidence from a surface node."""
        context = surface.context
        evidence: dict[str, Any] = {
            "target": self.target_key,
            "endpoint": surface.name,
            "parameter": str(surface.attributes.get("parameter") or surface.name or ""),
            "confidence": surface.confidence,
            "method": context.method,
            "content_type": context.content_type,
            "fetch_hint": context.fetch_hint,
            "object_hint": context.object_hint,
        }
        if surface.attributes.get("observed_status"):
            evidence["observed_status"] = str(surface.attributes["observed_status"])
        return evidence

    def _mutations_for(self, surface: SurfaceNode, depth: int) -> tuple[dict[str, Any], ...]:
        """Build bounded controlled request mutations for the surface vectors."""
        mutations: list[dict[str, Any]] = []
        context = surface.context
        if context.method and context.method.upper() in ("POST", "PUT"):
            mutations.append({"method": context.method.upper()})
        if context.fetch_hint:
            mutations.append({"parameter": "url"})
        return tuple(mutations[: max(0, depth)])

    def _workflow_security_properties(self, surface: SurfaceNode) -> tuple[str, ...]:
        """Return the security capabilities to evaluate for a workflow surface."""
        attributes = surface.attributes or {}
        explicit = attributes.get("security_properties")
        if isinstance(explicit, list):
            return tuple(str(item) for item in explicit)
        return ("authorization", "http-access-differential")

    def _publish(self, event_type: str, payload: dict[str, Any]) -> None:
        """Publish an attack event on the wired bus (best-effort)."""
        if self._event_bus is None:
            return
        with contextlib.suppress(Exception):
            from hunterx.domain.events import DomainEvent

            self._event_bus.publish(
                DomainEvent(
                    event_type=event_type,
                    payload=payload,
                    source="application.adaptive_attack",
                    mission_id=self.mission_id,
                )
            )


__all__ = ["AdaptiveAttackService"]
