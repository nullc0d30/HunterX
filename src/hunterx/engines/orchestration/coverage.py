# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission coverage model.

Computes coverage metrics for a mission: scope coverage, asset coverage, port
coverage, protocol coverage, technology coverage, endpoint coverage,
vulnerability coverage, validation coverage, tool coverage and evidence
coverage. Coverage is always expressed relative to the observed attack surface
and applicable capabilities — never as a raw tool count.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.orchestration.enums import CoverageKind


@dataclass(frozen=True, slots=True)
class CoverageMetric:
    """A single coverage metric.

    Attributes:
        kind: the coverage kind.
        observed: attack-surface items observed.
        expected: items expected to be covered.
        covered: items actually covered.
        fraction: ``covered / expected`` in ``[0, 1]`` (``1.0`` when expected is 0).

    """

    kind: CoverageKind
    observed: int = 0
    expected: int = 0
    covered: int = 0

    @property
    def fraction(self) -> float:
        """Return the coverage fraction in ``[0, 1]``."""
        if self.expected <= 0:
            return 1.0
        return max(0.0, min(1.0, self.covered / self.expected))

    @property
    def percent(self) -> float:
        """Return the coverage as a percentage."""
        return round(self.fraction * 100.0, 2)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "kind": self.kind.value,
            "observed": self.observed,
            "expected": self.expected,
            "covered": self.covered,
            "fraction": self.fraction,
            "percent": self.percent,
        }


@dataclass(slots=True)
class CoverageReport:
    """The full coverage report for a mission.

    Attributes:
        mission_id: owning mission.
        plan_id: the evaluated plan.
        metrics: coverage metrics keyed by :class:`CoverageKind`.
        blind_spots: documented coverage gaps/blind spots.

    """

    mission_id: str = ""
    plan_id: str = ""
    metrics: dict[CoverageKind, CoverageMetric] = field(default_factory=dict)
    blind_spots: list[str] = field(default_factory=list)

    def metric(self, kind: CoverageKind) -> CoverageMetric:
        """Return a metric, defaulting to an empty one."""
        return self.metrics.get(kind, CoverageMetric(kind=kind))

    def overall(self) -> float:
        """Return the overall coverage fraction (mean across non-trivial metrics)."""
        values = [metric.fraction for metric in self.metrics.values()]
        if not values:
            return 0.0
        return round(sum(values) / len(values), 4)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "metrics": {kind.value: metric.to_dict() for kind, metric in self.metrics.items()},
            "blind_spots": list(self.blind_spots),
            "overall": self.overall(),
        }


class CoverageModel:
    """Computes coverage metrics from a plan and a mission run.

    Usage::

        model = CoverageModel()
        report = model.compute(mission_id="m1", plan=plan, run=run_result)
    """

    def compute(
        self,
        *,
        mission_id: str,
        plan_id: str,
        targets: list[str] | None = None,
        planned_capabilities: list[str] | None = None,
        executed_capabilities: list[str] | None = None,
        executed_targets: list[str] | None = None,
        technologies: list[str] | None = None,
        planned_technologies: int = 0,
        endpoints: list[str] | None = None,
        planned_endpoints: int = 0,
        vulnerabilities: list[str] | None = None,
        validations: int = 0,
        planned_validations: int = 0,
        evidence: int = 0,
        tools: int = 0,
    ) -> CoverageReport:
        """Compute a coverage report from explicit observations.

        Args:
            mission_id: scoping mission identifier.
            plan_id: scoping plan identifier.
            targets: observed target identifiers.
            planned_capabilities: capabilities the plan requires.
            executed_capabilities: capabilities actually executed.
            executed_targets: targets actually reached by execution.
            technologies: observed technologies.
            planned_technologies: technologies expected from the surface.
            endpoints: observed endpoint kinds.
            planned_endpoints: endpoint kinds expected.
            vulnerabilities: observed vulnerabilities.
            validations: validations executed.
            planned_validations: validations planned.
            evidence: evidence records collected.
            tools: distinct tools executed.

        """
        targets = targets or []
        metrics: dict[CoverageKind, CoverageMetric] = {
            CoverageKind.SCOPE: CoverageMetric(
                kind=CoverageKind.SCOPE,
                observed=len(targets),
                expected=max(1, len(targets)),
                covered=len(set(executed_targets or []) & set(targets)) if executed_targets is not None else len(targets),
            ),
            CoverageKind.ASSET: CoverageMetric(
                kind=CoverageKind.ASSET,
                observed=len(targets),
                expected=max(1, len(targets)),
                covered=len(set(executed_targets or [])) if executed_targets is not None else len(targets),
            ),
            CoverageKind.TOOL: CoverageMetric(
                kind=CoverageKind.TOOL,
                observed=len(set(executed_capabilities or [])),
                expected=max(1, len(planned_capabilities or [])),
                covered=len(set(executed_capabilities or []) & set(planned_capabilities or [])),
            ),
            CoverageKind.TECHNOLOGY: CoverageMetric(
                kind=CoverageKind.TECHNOLOGY,
                observed=len(technologies or []),
                expected=max(1, planned_technologies),
                covered=min(len(technologies or []), max(0, planned_technologies)),
            ),
            CoverageKind.ENDPOINT: CoverageMetric(
                kind=CoverageKind.ENDPOINT,
                observed=len(endpoints or []),
                expected=max(1, planned_endpoints),
                covered=min(len(endpoints or []), max(0, planned_endpoints)),
            ),
            CoverageKind.VULNERABILITY: CoverageMetric(
                kind=CoverageKind.VULNERABILITY,
                observed=len(vulnerabilities or []),
                expected=max(1, len(vulnerabilities or [])),
                covered=len(vulnerabilities or []),
            ),
            CoverageKind.VALIDATION: CoverageMetric(
                kind=CoverageKind.VALIDATION,
                observed=validations,
                expected=max(1, planned_validations),
                covered=min(validations, max(0, planned_validations)),
            ),
            CoverageKind.EVIDENCE: CoverageMetric(
                kind=CoverageKind.EVIDENCE,
                observed=evidence,
                expected=max(1, evidence),
                covered=evidence,
            ),
            CoverageKind.PORT: CoverageMetric(kind=CoverageKind.PORT, observed=0, expected=0, covered=0),
            CoverageKind.PROTOCOL: CoverageMetric(kind=CoverageKind.PROTOCOL, observed=0, expected=0, covered=0),
        }
        blind_spots = self._blind_spots(metrics)
        return CoverageReport(
            mission_id=mission_id,
            plan_id=plan_id,
            metrics=metrics,
            blind_spots=blind_spots,
        )

    def from_run(
        self,
        *,
        mission_id: str,
        plan: Any,
        run: Any,
    ) -> CoverageReport:
        """Compute a coverage report from a plan and a mission run result."""
        plan_steps = plan.steps() if hasattr(plan, "steps") else ()
        capabilities = sorted({step.capability for step in plan_steps if step.capability})
        executed = sorted({outcome.tool_id for outcome in run.outcomes.values() if outcome.ok})
        targets = sorted({step.target for step in plan_steps if step.target})
        executed_steps = [step_id for step_id, outcome in run.outcomes.items() if outcome.ok]
        executed_capabilities = sorted(
            {step.capability for step in plan_steps if step.capability and step.step_id in executed_steps}
        )
        executed_targets = sorted({step.target for step in plan_steps if step.step_id in executed_steps})
        return self.compute(
            mission_id=mission_id,
            plan_id=plan.plan_id,
            targets=targets,
            planned_capabilities=capabilities,
            executed_capabilities=executed_capabilities,
            executed_targets=executed_targets,
            evidence=sum(outcome.evidence_count for outcome in run.outcomes.values()),
            tools=len(executed),
        )

    @staticmethod
    def _blind_spots(metrics: dict[CoverageKind, CoverageMetric]) -> list[str]:
        blind: list[str] = []
        for kind, metric in metrics.items():
            if metric.expected > 0 and metric.covered < metric.expected:
                blind.append(f"{kind.value}: covered {metric.covered}/{metric.expected}")
        return blind
