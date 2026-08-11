# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Layer (Sprint 023).

The layer composes the Sprint 023 engines — selection, planning, escalation,
evidence correlation, enforcement, reliability and target intelligence — into
one facade. Subsystems (mission orchestration, safe validation, proof strategy
selection) use this facade to answer "which tool, in what order, with what
enforcement, and what did we learn?".
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.tool_intelligence import (
    CanonicalObservation,
    ChainStatus,
    ChainStepResult,
    ChainStepState,
    CorrelatedEvidenceChain,
    EscalationDecision,
    EscalationLevel,
    TargetIntelligenceSnapshot,
    ToolAvailabilityReport,
    ToolAvailabilityStatus,
    ToolChain,
    ToolChainResult,
    ToolExecutionRecord,
    ToolSafetyClass,
    ToolSelection,
    ToolSelectionCriteria,
)
from hunterx.tools.intelligence.correlation import EvidenceCorrelator
from hunterx.tools.intelligence.enforcement import ToolEnforcementEngine
from hunterx.tools.intelligence.escalation import EscalationEngine
from hunterx.tools.intelligence.parsers import NormalizerRegistry, ParserRegistry, ToolRuntimeRegistry
from hunterx.tools.intelligence.planner import ToolSequencePlanner
from hunterx.tools.intelligence.reliability import ToolReliabilityTracker
from hunterx.tools.intelligence.selector import ToolSelector
from hunterx.tools.intelligence.target import TargetIntelligenceStore


class ToolIntelligenceLayer:
    """Facade over the Sprint 023 engines.

    Usage::

        layer = ToolIntelligenceLayer(
            registry=tip.registry,
            compatibility=tip.compatibility,
            selector=tip.selector,
        )
        selection = layer.select_best(criteria)
        chain = layer.plan("enum", capabilities=("web-crawling",))
    """

    def __init__(
        self,
        *,
        registry,
        compatibility,
        selector: ToolSelector | None = None,
        parsers: ParserRegistry | None = None,
        normalizers: NormalizerRegistry | None = None,
    ) -> None:
        self.registry = registry
        self.parsers = parsers or ParserRegistry()
        self.normalizers = normalizers or NormalizerRegistry()
        self.runtime = ToolRuntimeRegistry(self.parsers, self.normalizers)
        self.runtime.ensure_builtins()
        self.selector = selector or ToolSelector(registry, compatibility)
        self.planner = ToolSequencePlanner(self.selector, registry)
        self.escalations = EscalationEngine(registry, self.selector)
        self.enforcement = ToolEnforcementEngine()
        self.reliability = ToolReliabilityTracker(registry)
        self.targets = TargetIntelligenceStore()

    # -- selection ---------------------------------------------------------

    def select(
        self,
        criteria: ToolSelectionCriteria,
        *,
        authorization: ToolSafetyClass = ToolSafetyClass.HIGH_IMPACT,
    ) -> list[ToolSelection]:
        """Return ranked safety-aware selections."""
        return self.selector.select(criteria, authorization=authorization)

    def select_best(
        self,
        criteria: ToolSelectionCriteria,
        *,
        authorization: ToolSafetyClass = ToolSafetyClass.HIGH_IMPACT,
    ) -> ToolSelection:
        """Return the single best selection."""
        return self.selector.select_best(criteria, authorization=authorization)

    # -- planning ----------------------------------------------------------

    def plan(
        self,
        objective: str,
        *,
        capabilities: tuple[str, ...],
        chain_id: str = "",
        mission_id: str = "",
        scope: str = "",
        authorization: ToolSafetyClass = ToolSafetyClass.HIGH_IMPACT,
        inputs: dict[str, Any] | None = None,
    ) -> ToolChain:
        """Plan a dependency-aware tool chain for ``objective``."""
        return self.planner.plan(
            objective,
            capabilities=capabilities,
            chain_id=chain_id,
            mission_id=mission_id,
            scope=scope,
            authorization=authorization,
            inputs=inputs,
        )

    # -- escalation --------------------------------------------------------

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
        """Return the escalation decision for a tool at a level."""
        return self.escalations.escalate(
            tool_id=tool_id,
            level=level,
            capability=capability,
            authorization=authorization,
            scope_ok=scope_ok,
            evidence=evidence,
            reason=reason,
        )

    # -- enforcement -------------------------------------------------------

    def enforce(
        self,
        tool_id: str,
        *,
        authorization: ToolSafetyClass,
        schema=None,
        values: dict[str, Any],
        target: str = "",
        authorized_scope: tuple[str, ...] = (),
        available_memory_mb: float = 0.0,
        available_disk_mb: float = 0.0,
        safety=None,
        resources=None,
    ) -> dict[str, Any]:
        """Run all pre-execution gates; return validated input values.

        Raises:
            EnforcementViolation: when any gate fails.
            AuthorizationError: when authorization is required but not granted.

        """
        self.enforcement.enforce_safety(tool_id, authorization=authorization, safety=safety)
        if target:
            self.enforcement.enforce_scope(
                tool_id, target=target, authorized_scope=authorized_scope
            )
        validated = self.enforcement.validate_inputs(tool_id, schema, values)
        self.enforcement.enforce_resources(
            tool_id,
            required=resources,
            available_memory_mb=available_memory_mb,
            available_disk_mb=available_disk_mb,
        )
        return validated

    # -- evidence correlation ----------------------------------------------

    def correlate(self, observations: list[CanonicalObservation]) -> list[CorrelatedEvidenceChain]:
        """Correlate observations into evidence chains (respecting ceilings)."""
        correlator = EvidenceCorrelator(self._ceilings(observations))
        correlator.ingest_many(observations)
        return correlator.correlated_chains()

    def conflicts(self, observations: list[CanonicalObservation]):
        """Return conflicting evidence groups among ``observations``."""
        correlator = EvidenceCorrelator(self._ceilings(observations))
        correlator.ingest_many(observations)
        return correlator.conflicts()

    # -- target intelligence -----------------------------------------------

    def record_execution(
        self,
        *,
        tool_id: str,
        target: str,
        tool_version: str = "",
        mission_id: str = "",
        observations: tuple[CanonicalObservation, ...] = (),
        duration_ms: int = 0,
        status: str = "completed",
    ) -> ToolExecutionRecord:
        """Record an execution against a target and update reliability."""
        from hunterx.tools.intelligence.target import utc_now

        record = ToolExecutionRecord(
            execution_id=f"exec-{tool_id}-{abs(hash(utc_now()))}",
            tool_id=tool_id,
            tool_version=tool_version,
            mission_id=mission_id,
            target=target,
            observations=tuple(o.observation_id for o in observations),
            status=status,
            started_at=utc_now(),
            completed_at=utc_now(),
            duration_ms=duration_ms,
        )
        self.targets.record(record, list(observations))
        if status == "completed":
            self.reliability.record_success(tool_id, duration_ms=duration_ms)
        else:
            self.reliability.record_failure(tool_id)
        return record

    def snapshot(self, target: str) -> TargetIntelligenceSnapshot:
        """Return the current intelligence snapshot for ``target``."""
        return self.targets.snapshot(target)

    def report_availability(
        self,
        tool_id: str,
        status: ToolAvailabilityStatus,
        *,
        reason: str = "",
    ) -> ToolAvailabilityReport:
        """Report a capability availability status."""
        return self.reliability.report_availability(tool_id, status, reason=reason)

    # -- helpers -----------------------------------------------------------

    def _ceilings(self, observations: list[CanonicalObservation]) -> dict[str, Any]:
        ceilings: dict[str, Any] = {}
        for observation in observations:
            if observation.tool_id in ceilings:
                continue
            ceiling = self.registry.get_confidence_ceiling(observation.tool_id)
            if ceiling is not None:
                ceilings[observation.tool_id] = ceiling
        return ceilings

    def estimate(self, chain: ToolChain) -> ToolChainResult:
        """Produce a planned (not executed) chain result for estimation."""
        step_results = tuple(
            ChainStepResult(
                step_id=step.step_id,
                tool_id=step.tool_id,
                status=ChainStepState.PENDING,
            )
            for step in chain.steps
        )
        return ToolChainResult(
            chain_id=chain.chain_id,
            status=ChainStatus.PLANNED,
            step_results=step_results,
            completed_steps=(),
            failed_steps=(),
            skipped_steps=(),
        )


__all__ = ["ToolIntelligenceLayer"]
