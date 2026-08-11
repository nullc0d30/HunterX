# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence API.

The Tool Intelligence Platform (TIP) facade. Composes every TIP engine behind
a single :class:`~hunterx.domain.ports.tool_intelligence.ToolIntelligencePort`
implementation, giving every HunterX subsystem one entry point to query tool
intelligence.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.exceptions import ToolNotFoundError
from hunterx.domain.ports.tool_intelligence import ToolIntelligencePort
from hunterx.domain.tool_intelligence import (
    CanonicalObservation,
    CorrelatedEvidenceChain,
    EscalationDecision,
    EscalationLevel,
    TargetIntelligenceSnapshot,
    ToolAvailabilityReport,
    ToolAvailabilityStatus,
    ToolCapability,
    ToolChain,
    ToolCompatibility,
    ToolConfidenceCeiling,
    ToolEvidenceMapping,
    ToolExecutionRecord,
    ToolHealthStats,
    ToolKnowledge,
    ToolMetadata,
    ToolPerformanceStats,
    ToolProofCapability,
    ToolRecommendation,
    ToolReliabilityStats,
    ToolRuntimeState,
    ToolSafetyClass,
    ToolSelection,
    ToolSelectionCriteria,
    ToolSelectionResult,
    ToolState,
    ToolTaxonomyNode,
)
from hunterx.tools.intelligence.capability import CapabilityEngine
from hunterx.tools.intelligence.compatibility import CompatibilityEngine, CompatibilityResult
from hunterx.tools.intelligence.dependency import DependencyEngine
from hunterx.tools.intelligence.docs import ToolDocumentationGenerator
from hunterx.tools.intelligence.health import ToolHealthMonitor
from hunterx.tools.intelligence.layer import ToolIntelligenceLayer
from hunterx.tools.intelligence.lifecycle import ToolLifecycleManager
from hunterx.tools.intelligence.performance import ToolPerformanceAnalyzer
from hunterx.tools.intelligence.recommendation import ToolRecommendationEngine
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.selection import ToolSelectionEngine
from hunterx.tools.intelligence.selector import ToolSelector
from hunterx.tools.intelligence.state import ToolStateMachine
from hunterx.tools.intelligence.taxonomy import ToolTaxonomy
from hunterx.tools.intelligence.validation import (
    ToolValidationFramework,
    ValidationReport,
)
from hunterx.tools.intelligence.vocabulary import CapabilityVocabulary


class ToolIntelligenceAPI(ToolIntelligencePort):
    """Facade implementing :class:`ToolIntelligencePort`.

    Usage::

        tip = ToolIntelligenceAPI()
        tip.register_tool(metadata, knowledge, compatibility)
        tip.select(ToolSelectionCriteria(required_capabilities=("vulnerability-scan",)))
    """

    def __init__(self, registry: ToolIntelligenceRegistry | None = None) -> None:
        self.registry = registry or ToolIntelligenceRegistry()
        self.taxonomy_model = ToolTaxonomy()
        self.vocabulary = CapabilityVocabulary()
        self.capabilities_engine = CapabilityEngine(self.registry, self.taxonomy_model)
        self.capabilities_engine.sync_taxonomy()
        self.dependencies = DependencyEngine(self.registry)
        self.compatibility = CompatibilityEngine(self.registry)
        self.state_machine = ToolStateMachine()
        self.health_monitor = ToolHealthMonitor(self.registry)
        self.performance_analyzer = ToolPerformanceAnalyzer(self.registry)
        self.selection = ToolSelectionEngine(self.registry, self.compatibility)
        self.selector = ToolSelector(self.registry, self.compatibility, base=self.selection)
        self.layer = ToolIntelligenceLayer(
            registry=self.registry,
            compatibility=self.compatibility,
            selector=self.selector,
        )
        self.recommendations = ToolRecommendationEngine(
            self.registry, self.selection, self.dependencies, vocabulary=self.vocabulary
        )
        self.lifecycle = ToolLifecycleManager(self.registry, self.state_machine, self.health_monitor)
        self.validation = ToolValidationFramework(self.registry, self.compatibility)
        self.docs = ToolDocumentationGenerator(self.registry)

    # -- registration (mutating) -------------------------------------------

    def register_tool(
        self,
        metadata: ToolMetadata,
        *,
        knowledge: ToolKnowledge | None = None,
        compatibility: ToolCompatibility | None = None,
    ) -> None:
        """Register a tool with optional knowledge and compatibility profiles."""
        self.lifecycle.register(metadata)
        if knowledge is not None:
            self.registry.register_knowledge(knowledge)
        if compatibility is not None:
            self.registry.register_compatibility(compatibility)

    def register_knowledge(self, knowledge: ToolKnowledge) -> None:
        """Register or replace a knowledge profile."""
        self.registry.register_knowledge(knowledge)

    def register_capability(self, capability: ToolCapability) -> None:
        """Register a custom capability definition."""
        self.capabilities_engine.register(capability)

    def unregister(self, tool_id: str) -> None:
        """Remove a tool and its intelligence records."""
        self.lifecycle.unregister(tool_id)

    # -- registry queries --------------------------------------------------

    def get_tool(self, tool_id: str) -> ToolMetadata | None:
        """Return metadata for ``tool_id`` or ``None``."""
        return self.registry.get_metadata(tool_id)

    def list_tools(self) -> list[ToolMetadata]:
        """Return metadata for every registered tool."""
        return self.registry.list_metadata()

    def get_knowledge(self, tool_id: str) -> ToolKnowledge | None:
        """Return the knowledge profile for ``tool_id`` or ``None``."""
        return self.registry.get_knowledge(tool_id)

    def search_tools(self, term: str) -> list[ToolMetadata]:
        """Return tools whose id/name/tags match ``term``."""
        return self.registry.search(term)

    def get_state(self, tool_id: str) -> ToolRuntimeState | None:
        """Return the runtime state for ``tool_id`` or ``None``."""
        return self.registry.get_state(tool_id)

    # -- capabilities and taxonomy ----------------------------------------

    def tools_by_capability(self, capability_id: str) -> list[str]:
        """Return tool ids that provide ``capability_id``."""
        return self.registry.providers_for(capability_id)

    def capabilities(self) -> list[str]:
        """Return the known capability ids."""
        return self.capabilities_engine.capabilities()

    def taxonomy(self) -> ToolTaxonomyNode:
        """Return the root of the tool taxonomy tree."""
        return self.taxonomy_model.root

    def search_capabilities(self, term: str) -> list[ToolCapability]:
        """Search capability definitions by id/name/description."""
        return self.capabilities_engine.search(term)

    # -- analysis ----------------------------------------------------------

    def resolve_dependencies(self, tool_id: str) -> list[str]:
        """Return tool ids that must run before ``tool_id`` (topological)."""
        return self.dependencies.resolve_dependencies(tool_id)

    def check_compatibility(
        self,
        tool_id: str,
        *,
        os_name: str = "",
        architecture: str = "",
        docker: bool = False,
        air_gapped: bool = False,
        cloud: bool = False,
    ) -> ToolCompatibility:
        """Return the compatibility assessment for ``tool_id``.

        If the tool has no declared compatibility profile, an unrestricted
        profile is returned.
        """
        profile = self.registry.get_compatibility(tool_id)
        if profile is not None:
            return profile
        return ToolCompatibility(tool_id=tool_id)

    def compatibility_report(
        self,
        tool_id: str,
        *,
        os_name: str = "",
        architecture: str = "",
        docker: bool = False,
        air_gapped: bool = False,
        cloud: bool = False,
    ) -> CompatibilityResult:
        """Return a full compatibility verdict for ``tool_id``."""
        if self.registry.get_metadata(tool_id) is None:
            raise ToolNotFoundError(tool_id)
        return self.compatibility.check(
            tool_id,
            os_name=os_name,
            architecture=architecture,
            docker=docker,
            air_gapped=air_gapped,
            cloud=cloud,
        )

    def health(self, tool_id: str) -> ToolHealthStats | None:
        """Return live health stats for ``tool_id`` or ``None``."""
        return self.health_monitor.get(tool_id)

    def performance(self, tool_id: str) -> ToolPerformanceStats | None:
        """Return historical performance stats for ``tool_id`` or ``None``."""
        return self.performance_analyzer.get(tool_id)

    # -- decision support --------------------------------------------------

    def select(self, criteria: ToolSelectionCriteria) -> list[ToolSelectionResult]:
        """Rank tools matching ``criteria``, best first."""
        return self.selection.select(criteria)

    def select_intelligence(
        self,
        criteria: ToolSelectionCriteria,
        *,
        authorization: ToolSafetyClass = ToolSafetyClass.HIGH_IMPACT,
        authorization_granted: bool = False,
    ) -> list[ToolSelection]:
        """Return ranked, safety-aware :class:`ToolSelection` results.

        This is the Sprint 023 selection surface. Tools whose safety class
        exceeds ``authorization`` (or that require un-granted authorization)
        are excluded.
        """
        return self.selector.select(
            criteria,
            authorization=authorization,
            authorization_granted=authorization_granted,
        )

    def plan_chain(
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
        """Plan a dependency-aware :class:`ToolChain` for ``objective``."""
        return self.layer.plan(
            objective,
            capabilities=capabilities,
            chain_id=chain_id,
            mission_id=mission_id,
            scope=scope,
            authorization=authorization,
            inputs=inputs,
        )

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
        """Return the escalation decision for ``tool_id`` at ``level``."""
        return self.layer.escalate(
            tool_id=tool_id,
            level=level,
            capability=capability,
            authorization=authorization,
            scope_ok=scope_ok,
            evidence=evidence,
            reason=reason,
        )

    def enforce_execution(
        self,
        tool_id: str,
        *,
        authorization: ToolSafetyClass,
        values: dict[str, Any],
        target: str = "",
        authorized_scope: tuple[str, ...] = (),
        available_memory_mb: float = 0.0,
        available_disk_mb: float = 0.0,
    ) -> dict[str, Any]:
        """Run all pre-execution enforcement gates for ``tool_id``.

        Returns validated input values or raises :class:`EnforcementViolation`
        / :class:`AuthorizationError`.
        """
        knowledge = self.registry.get_knowledge(tool_id)
        safety = knowledge.safety_profile if knowledge is not None else None
        resources = knowledge.resource_requirements if knowledge is not None else None
        schema = knowledge.input_schema if knowledge is not None else None
        return self.layer.enforce(
            tool_id,
            authorization=authorization,
            schema=schema,
            values=values,
            target=target,
            authorized_scope=authorized_scope,
            available_memory_mb=available_memory_mb,
            available_disk_mb=available_disk_mb,
            safety=safety,
            resources=resources,
        )

    def correlate(
        self,
        observations: list[CanonicalObservation],
    ) -> list[CorrelatedEvidenceChain]:
        """Correlate canonical observations into evidence chains."""
        return self.layer.correlate(observations)

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
        """Record an execution against a target in the target intelligence store."""
        return self.layer.record_execution(
            tool_id=tool_id,
            target=target,
            tool_version=tool_version,
            mission_id=mission_id,
            observations=observations,
            duration_ms=duration_ms,
            status=status,
        )

    def target_snapshot(self, target: str) -> TargetIntelligenceSnapshot:
        """Return the current intelligence snapshot for ``target``."""
        return self.layer.snapshot(target)

    def report_availability(
        self,
        tool_id: str,
        status: ToolAvailabilityStatus,
        *,
        reason: str = "",
    ) -> ToolAvailabilityReport:
        """Report a capability availability status for ``tool_id``."""
        return self.layer.report_availability(tool_id, status, reason=reason)

    def reliability(self, tool_id: str) -> ToolReliabilityStats | None:
        """Return reliability stats for ``tool_id`` or ``None``."""
        return self.layer.reliability.get(tool_id)

    def register_evidence_mapping(self, mapping: ToolEvidenceMapping) -> None:
        """Register an evidence mapping for a tool."""
        self.registry.register_evidence_mapping(mapping)

    def register_proof_capability(self, capability: ToolProofCapability) -> None:
        """Register a proof capability for a tool."""
        self.registry.register_proof_capability(capability)

    def register_confidence_ceiling(self, ceiling: ToolConfidenceCeiling) -> None:
        """Register a confidence contribution ceiling for a tool."""
        self.registry.register_confidence_ceiling(ceiling)

    def recommend(self, capability_id: str) -> list[ToolRecommendation]:
        """Return recommendations for a capability (best/alternative/fallback)."""
        return self.recommendations.recommend(capability_id)

    def validate(self, tool_id: str) -> ValidationReport:
        """Run the full validation framework for ``tool_id``."""
        if self.registry.get_metadata(tool_id) is None:
            raise ToolNotFoundError(tool_id)
        return self.validation.validate(tool_id)

    # -- lifecycle convenience (thin wrappers) -----------------------------

    def install(self, tool_id: str, *, version: str = "") -> ToolRuntimeState:
        """Install a registered tool."""
        return self.lifecycle.install(tool_id, version=version)

    def verify(self, tool_id: str, *, ok: bool = True) -> ToolRuntimeState:
        """Verify an installed tool."""
        return self.lifecycle.verify(tool_id, ok=ok)

    def make_available(self, tool_id: str) -> ToolRuntimeState:
        """Make a verified tool available for execution."""
        return self.lifecycle.make_available(tool_id)

    def disable(self, tool_id: str) -> ToolRuntimeState:
        """Disable a tool."""
        return self.lifecycle.disable(tool_id)

    def enable(self, tool_id: str) -> ToolRuntimeState:
        """Re-enable a disabled tool."""
        return self.lifecycle.enable(tool_id)

    def deprecate(self, tool_id: str) -> ToolRuntimeState:
        """Mark a tool as deprecated."""
        return self.lifecycle.deprecate(tool_id)

    def is_usable(self, tool_id: str) -> bool:
        """Return ``True`` when the tool is installed and usable."""
        return self.lifecycle.is_usable(tool_id)

    def state_of(self, tool_id: str) -> ToolState | None:
        """Return the current lifecycle state of ``tool_id`` or ``None``."""
        state = self.registry.get_state(tool_id)
        return state.state if state is not None else None

    # -- records (health/performance) --------------------------------------

    def record_success(self, tool_id: str, *, duration_ms: int = 0) -> ToolHealthStats:
        """Record a successful execution for health tracking."""
        return self.health_monitor.record_success(tool_id, duration_ms=duration_ms)

    def record_failure(self, tool_id: str, *, crash: bool = False, timeout: bool = False) -> ToolHealthStats:
        """Record a failed execution for health tracking."""
        return self.health_monitor.record_failure(tool_id, crash=crash, timeout=timeout)

    def record_performance(
        self,
        tool_id: str,
        *,
        duration_ms: int = 0,
        findings: int = 0,
        succeeded: bool = True,
        cost: float = 0.0,
    ) -> ToolPerformanceStats:
        """Record an execution outcome for performance analysis."""
        return self.performance_analyzer.record_execution(
            tool_id,
            duration_ms=duration_ms,
            findings=findings,
            succeeded=succeeded,
            cost=cost,
        )

    def generate_docs(self, tool_id: str) -> str:
        """Generate a Markdown reference page for ``tool_id``."""
        if self.registry.get_metadata(tool_id) is None:
            raise ToolNotFoundError(tool_id)
        return self.docs.generate(tool_id)
