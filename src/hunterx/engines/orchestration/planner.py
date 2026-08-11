# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission planner.

Consumes target intelligence, scope, mission type, known technologies, known
services, known endpoints, cloud intelligence and tool capabilities, and
produces a canonical :class:`ExecutionPlan`. The planner applies the reusable
mission phases (PHASE 0 … PHASE 12) with adaptive branching: only the phases
and steps that are relevant to the observed attack surface are included. The
planner never executes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.orchestration.enums import MissionPhaseKind, MissionType
from hunterx.domain.orchestration.models import (
    ExecutionPlan,
    MissionScope,
    MissionStep,
    Phase,
    Policies,
)
from hunterx.shared.ids import generate_id


@dataclass(slots=True)
class IntelligenceSummary:
    """A compact summary of mission intelligence consumed by the planner.

    Attributes:
        mission_type: the mission type (drives phase selection).
        technologies: known technology ids / product:version tokens.
        services: known services (``http``, ``https``, ``dns``, ...).
        endpoints: known endpoint kinds (``web``, ``api``, ``js``, ``cloud``).
        providers: known cloud providers.
        targets: known target identifiers.
        vulnerabilities: known potential vulnerabilities.

    """

    mission_type: MissionType = MissionType.VULNERABILITY_ASSESSMENT
    technologies: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    endpoints: tuple[str, ...] = ()
    providers: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    vulnerabilities: tuple[str, ...] = ()
    scope: MissionScope = field(default_factory=MissionScope)

    def has(self, kind: str, value: str) -> bool:
        """Return ``True`` when ``value`` is present for ``kind``."""
        bucket = getattr(self, kind, ())
        return value in bucket


#: Canonical capabilities per phase kind (step-level capability needs).
_PHASE_CAPABILITIES: dict[MissionPhaseKind, tuple[str, ...]] = {
    MissionPhaseKind.RECONNAISSANCE: ("subdomain-discovery", "host-discovery", "dns-records"),
    MissionPhaseKind.ASSET_DISCOVERY: ("host-discovery", "live-host"),
    MissionPhaseKind.SERVICE_DISCOVERY: ("port-discovery", "service-enumeration"),
    MissionPhaseKind.TECHNOLOGY_DISCOVERY: ("technology-detection",),
    MissionPhaseKind.ATTACK_SURFACE_MAPPING: (
        "web-crawling",
        "url-discovery",
        "content-discovery",
        "api-discovery",
        "javascript-analysis",
        "cloud-enumeration",
    ),
    MissionPhaseKind.VULNERABILITY_INTELLIGENCE: ("vulnerability-knowledge", "cve-intelligence"),
    MissionPhaseKind.VULNERABILITY_HYPOTHESIS: ("vulnerability-hypothesis",),
    MissionPhaseKind.SAFE_VALIDATION: ("passive-probe", "version-probe", "error-behavior-probe"),
    MissionPhaseKind.CORRELATION: ("correlation",),
    MissionPhaseKind.RISK_PRIORITIZATION: ("risk-prioritization",),
    MissionPhaseKind.EVIDENCE_CONSOLIDATION: ("evidence-consolidation",),
    MissionPhaseKind.REPORTING: ("reporting",),
}


class MissionPlanner:
    """Produces an :class:`ExecutionPlan` from mission intelligence.

    The planner is adaptive: phases are selected based on the mission type and
    the observed attack surface. Steps are expanded per target with canonical
    capabilities; tool binding happens later in the tool-selection phase.

    Usage::

        plan = planner.plan(
            mission_id="m1",
            objective="assess example.com",
            intelligence=summary,
            scope=mission.scope,
            policies=mission.policies,
        )
    """

    def __init__(self) -> None:
        self._count = 0

    def plan(
        self,
        *,
        mission_id: str,
        objective: str,
        intelligence: IntelligenceSummary,
        scope: MissionScope | None = None,
        policies: Policies | None = None,
        plan_id: str | None = None,
    ) -> ExecutionPlan:
        """Build an execution plan for a mission."""
        effective_scope = scope or intelligence.scope
        phases = self._select_phases(intelligence)
        phases = self._expand_steps(phases, intelligence)
        return ExecutionPlan(
            plan_id=plan_id or generate_id(),
            mission_id=mission_id,
            objective=objective,
            phases=tuple(phases),
            scope=effective_scope,
            policies=policies or Policies(),
            version=1,
        )

    # -- phase selection ----------------------------------------------------

    def _select_phases(self, intelligence: IntelligenceSummary) -> list[Phase]:
        mission_type = intelligence.mission_type
        phases: list[Phase] = []

        recon = self._phase(MissionPhaseKind.RECONNAISSANCE, intelligence)
        asset = self._phase(MissionPhaseKind.ASSET_DISCOVERY, intelligence)
        service = self._phase(MissionPhaseKind.SERVICE_DISCOVERY, intelligence)
        tech = self._phase(MissionPhaseKind.TECHNOLOGY_DISCOVERY, intelligence)
        surface = self._phase(MissionPhaseKind.ATTACK_SURFACE_MAPPING, intelligence)
        vuln_knowledge = self._phase(MissionPhaseKind.VULNERABILITY_INTELLIGENCE, intelligence)
        hypothesis = self._phase(MissionPhaseKind.VULNERABILITY_HYPOTHESIS, intelligence)
        validation = self._phase(MissionPhaseKind.SAFE_VALIDATION, intelligence)
        correlation = self._phase(MissionPhaseKind.CORRELATION, intelligence)
        risk = self._phase(MissionPhaseKind.RISK_PRIORITIZATION, intelligence)
        evidence = self._phase(MissionPhaseKind.EVIDENCE_CONSOLIDATION, intelligence)
        reporting = self._phase(MissionPhaseKind.REPORTING, intelligence)

        phases.append(recon)
        phases.append(asset)
        phases.append(service)

        tech_steps: list[MissionStep] = []
        for target in intelligence.targets or ():
            tech_steps.append(
                MissionStep(
                    phase_id=tech.phase_id,
                    action="technology.discover",
                    capability="technology-detection",
                    target=target,
                    target_type=_target_type(target),
                    evidence_requirements=("technology", "version"),
                    success_criteria=("technology observed",),
                )
            )
        tech = _replace_phase(tech, steps=tuple(tech_steps))
        phases.append(tech)

        has_web = any(kind in intelligence.endpoints for kind in ("web", "http", "js")) or any(
            service in intelligence.services for service in ("http", "https")
        )
        has_api = "api" in intelligence.endpoints
        has_js = "js" in intelligence.endpoints or "javascript" in intelligence.endpoints
        has_cloud = "cloud" in intelligence.endpoints or bool(intelligence.providers)

        surface_steps = _surface_steps(surface.phase_id, has_web, has_api, has_js, has_cloud, intelligence.targets)
        if surface_steps:
            surface = _replace_phase(surface, steps=surface_steps)
            phases.append(surface)

        if mission_type in (
            MissionType.BUG_BOUNTY,
            MissionType.WEB_PENTEST,
            MissionType.API_PENTEST,
            MissionType.EXTERNAL_ASSESSMENT,
            MissionType.INTERNAL_ASSESSMENT,
            MissionType.CLOUD_ASSESSMENT,
            MissionType.CONTINUOUS_ATTACK_SURFACE_MONITORING,
            MissionType.VULNERABILITY_ASSESSMENT,
        ):
            phases.append(vuln_knowledge)

        if intelligence.vulnerabilities:
            phases.append(hypothesis)
            phases.append(validation)

        phases.append(correlation)
        phases.append(risk)
        phases.append(evidence)
        phases.append(reporting)

        ordered = self._order_by_kind(phases)
        return self._wire_dependencies(ordered)

    def _phase(self, kind: MissionPhaseKind, intelligence: IntelligenceSummary) -> Phase:
        return Phase(
            phase_id=f"{kind.value}-{self._next()}",
            kind=kind,
            name=kind.value.replace("-", " ").title(),
        )

    def _expand_steps(self, phases: list[Phase], intelligence: IntelligenceSummary) -> list[Phase]:
        """Attach per-target steps to recon/asset/service phases."""
        targets = intelligence.targets or ()
        expanded: list[Phase] = []
        for phase in phases:
            if phase.kind in (
                MissionPhaseKind.RECONNAISSANCE,
                MissionPhaseKind.ASSET_DISCOVERY,
                MissionPhaseKind.SERVICE_DISCOVERY,
            ):
                steps = []
                for target in targets:
                    steps.extend(self._target_steps(phase, target))
                expanded.append(_replace_phase(phase, steps=tuple(steps)))
            else:
                expanded.append(phase)
        return expanded

    def _target_steps(self, phase: Phase, target: str) -> list[MissionStep]:
        capabilities = _PHASE_CAPABILITIES.get(phase.kind, ())
        steps: list[MissionStep] = []
        previous = ""
        for capability in capabilities:
            step = MissionStep(
                phase_id=phase.phase_id,
                action=f"{phase.kind.value}.{capability}",
                capability=capability,
                target=target,
                target_type=_target_type(target),
                depends_on=(previous,) if previous else (),
                retryable=True,
            )
            steps.append(step)
            previous = step.step_id
        return steps

    def _order_by_kind(self, phases: list[Phase]) -> list[Phase]:
        """Order phases by the canonical PHASE 0…12 sequence."""
        rank = {
            MissionPhaseKind.SCOPE: 0,
            MissionPhaseKind.RECONNAISSANCE: 1,
            MissionPhaseKind.ASSET_DISCOVERY: 2,
            MissionPhaseKind.SERVICE_DISCOVERY: 3,
            MissionPhaseKind.TECHNOLOGY_DISCOVERY: 4,
            MissionPhaseKind.ATTACK_SURFACE_MAPPING: 5,
            MissionPhaseKind.VULNERABILITY_INTELLIGENCE: 6,
            MissionPhaseKind.VULNERABILITY_HYPOTHESIS: 7,
            MissionPhaseKind.SAFE_VALIDATION: 8,
            MissionPhaseKind.CORRELATION: 9,
            MissionPhaseKind.RISK_PRIORITIZATION: 10,
            MissionPhaseKind.EVIDENCE_CONSOLIDATION: 11,
            MissionPhaseKind.REPORTING: 12,
        }
        return sorted(phases, key=lambda phase: rank.get(phase.kind, 99))

    def _wire_dependencies(self, phases: list[Phase]) -> list[Phase]:
        """Wire phase dependencies onto the preceding phase id."""
        ids = [phase.phase_id for phase in phases]
        wired: list[Phase] = []
        for index, phase in enumerate(phases):
            depends: tuple[str, ...] = ()
            if index > 0:
                depends = (ids[index - 1],)
            wired.append(_replace_phase(phase, depends_on=depends))
        return wired

    def _next(self) -> int:
        self._count += 1
        return self._count


def _surface_steps(phase_id: str, has_web: bool, has_api: bool, has_js: bool, has_cloud: bool, targets: tuple[str, ...] = ()) -> list[MissionStep]:
    """Build adaptive attack-surface steps based on the observed surface."""
    steps: list[MissionStep] = []
    if has_web:
        for target in targets or ():
            steps.append(MissionStep(phase_id=phase_id, action="surface.crawl", capability="web-crawling", target=target, target_type=_target_type(target)))
            steps.append(MissionStep(phase_id=phase_id, action="surface.urls", capability="url-discovery", target=target, target_type=_target_type(target)))
            steps.append(MissionStep(phase_id=phase_id, action="surface.content", capability="content-discovery", target=target, target_type=_target_type(target)))
    if has_api:
        for target in targets or ():
            steps.append(MissionStep(phase_id=phase_id, action="surface.api", capability="api-discovery", target=target, target_type=_target_type(target)))
    if has_js:
        for target in targets or ():
            steps.append(MissionStep(phase_id=phase_id, action="surface.js", capability="javascript-analysis", target=target, target_type=_target_type(target)))
    if has_cloud:
        for target in targets or ():
            steps.append(MissionStep(phase_id=phase_id, action="surface.cloud", capability="cloud-enumeration", target=target, target_type=_target_type(target)))
    return steps


def _replace_phase(phase: Phase, **changes: Any) -> Phase:
    from dataclasses import replace

    return replace(phase, **changes)


def _target_type(target: str) -> str:
    """Infer a canonical target type from a target identifier."""
    value = target.strip().lower()
    if value.startswith(("http://", "https://")):
        return "url"
    if value.startswith("arn:"):
        return "cloud"
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        if "/" in value:
            try:
                ipaddress.ip_network(value, strict=False)
                return "cidr"
            except ValueError:
                pass
        return "domain"
