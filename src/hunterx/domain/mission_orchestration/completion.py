# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Objective-aware mission completion contract.

The real-run regression: a ``full_security_assessment`` reached
``stop_condition=coverage_target_achieved`` at 76.47% coverage while 67 of 69
hypotheses were still open, active testing had not been performed, browser
coverage was NOT_ASSESSED and no attack paths had been evaluated. Coverage
measured what was *planned/tested*, not whether the target was assessed.

This module defines the **completion contract**: the objective-specific gates a
mission must satisfy before any coverage-derived condition may become terminal.
Coverage remains an input, but it is no longer sufficient on its own.

A classified-but-open hypothesis (``DEFERRED``/``BLOCKED`` with a recorded
reason) is acceptable: the assessment is then reported as partial/blocked —
never as complete. An *unclassified actionable* hypothesis always blocks
completion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunterx.domain.adaptive_mission_planning.enums import MissionObjective

#: Hypothesis states that still require attention (unsettled).
_OPEN_STATES = frozenset({"proposed", "supported", "weakly_supported", "inconclusive", "novel_behavior"})


@dataclass(frozen=True, slots=True)
class CompletionGate:
    """One completion gate: a named, explainable requirement."""

    name: str
    satisfied: bool
    reason: str

    def to_dict(self) -> dict[str, str | bool]:
        """Serialize to a JSON-safe mapping."""
        return {"name": self.name, "satisfied": self.satisfied, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class CompletionAssessment:
    """Result of evaluating the mission completion contract."""

    satisfied: bool
    gates: tuple[CompletionGate, ...]

    def unmet(self) -> list[str]:
        """Return the names of the gates that are not satisfied."""
        return [gate.name for gate in self.gates if not gate.satisfied]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "satisfied": self.satisfied,
            "gates": [gate.to_dict() for gate in self.gates],
            "unmet": self.unmet(),
        }


def _is_high_value(hypothesis: Any) -> bool:
    """Return ``True`` when an open hypothesis is actionable high-value work.

    Matches the policy engine's definition: priority >= 0.75, or an open
    class-specific vulnerability candidate (concrete, probeable work). Such a
    hypothesis must never be silently left open.
    """
    if hypothesis.priority >= 0.75:
        return True
    provenance = hypothesis.provenance or {}
    vulnerability_class = str(provenance.get("vulnerability_class") or "").strip()
    if not vulnerability_class:
        return False
    from hunterx.domain.vulnerability_capability.registry import is_vulnerability_class

    return is_vulnerability_class(vulnerability_class)


def _actionable_open_hypotheses(mission: Any) -> list[Any]:
    """Return open hypotheses that are actionable and NOT explicitly classified.

    ``DEFERRED``/``BLOCKED`` hypotheses carry a recorded reason and do not block
    completion (the assessment is reported partial/blocked instead). Open
    high-value / vulnerability-class hypotheses that are still merely
    PROPOSED/SUPPORTED/etc. block completion until they are tested or
    classified.
    """
    return [
        hypothesis
        for hypothesis in mission.hypotheses
        if hypothesis.state.value in _OPEN_STATES and _is_high_value(hypothesis)
    ]


def _browser_gate(mission: Any) -> CompletionGate:
    """Return the browser-testing gate.

    The runner records a ``browser_testing`` coverage cell at mission start with
    an explicit verdict (``available`` with an executable, or an explicit
    unavailable/not-applicable reason). A web target whose browser dimension is
    NOT_ASSESSED without a recorded classification blocks completion; an
    explicitly unavailable browser is an accepted classification (reported as
    partial, never complete-with-everything).
    """
    cell = None
    coverage = getattr(mission, "coverage", None) or {}
    for cells in coverage.values():
        candidate = cells.get("browser_testing")
        if candidate is not None:
            cell = candidate
            break
    if cell is None:
        return CompletionGate("browser", False, "browser-testing dimension was never evaluated")
    state = getattr(cell, "state", None)
    state_value = getattr(state, "value", state) if state is not None else None
    notes = str(getattr(cell, "notes", "") or "")
    if state_value == "tested":
        return CompletionGate("browser", True, "browser testing performed")
    if state_value in ("not_assessed",) and notes:
        return CompletionGate("browser", True, f"browser testing explicitly classified: {notes}")
    return CompletionGate("browser", False, f"browser testing NOT_ASSESSED without a recorded classification (state={state_value})")


def _active_testing_gate(mission: Any) -> CompletionGate:
    """Return the active-testing gate.

    Active testing is *applicable* when an evidence-backed vulnerability
    hypothesis exists or a probeable surface (endpoints/parameters) was
    discovered. When applicable, at least one targeted probe must have been
    executed — otherwise the assessment is incomplete.
    """
    vuln_hypotheses = [
        hypothesis
        for hypothesis in mission.hypotheses
        if (hypothesis.provenance or {}).get("vulnerability_class")
    ]
    probeable_surface = bool(getattr(mission.context, "endpoints", None)) or bool(
        getattr(mission.context, "parameters", None)
    )
    applicable = bool(vuln_hypotheses) or probeable_surface
    if not applicable:
        return CompletionGate("active_testing", True, "active testing not applicable (no probeable surface)")
    probes = sum(
        1 for observation in mission.observations if observation.observation_type == "probe"
    )
    if probes > 0:
        return CompletionGate("active_testing", True, f"active testing performed ({probes} probes)")
    return CompletionGate(
        "active_testing",
        False,
        "active testing applicable but no probe was executed (evidence-backed hypotheses untested)",
    )


def _attack_path_gate(mission: Any) -> CompletionGate:
    """Return the attack-path evaluation gate.

    Attack paths are evaluated whenever a surface (services/endpoints) exists;
    structural chains are recorded as ``surface_relationships`` and
    evidence-backed chains as ``attack_paths``. A discovered surface with
    neither means the dimension was never evaluated.
    """
    surface_exists = bool(getattr(mission.context, "services", None)) or bool(
        getattr(mission.context, "endpoints", None)
    )
    if not surface_exists:
        return CompletionGate("attack_paths", True, "attack-path evaluation not applicable (no surface)")
    evaluated = bool(getattr(mission.context, "attack_paths", None)) or bool(
        getattr(mission.context, "surface_relationships", None)
    )
    return CompletionGate(
        "attack_paths",
        evaluated,
        "attack paths evaluated" if evaluated else "attack-surface dimension never evaluated",
    )


def _validation_gate(mission: Any) -> CompletionGate:
    """Return the validation gate.

    Validation is applicable when a hypothesis reached SUPPORTED or a finding
    exists. When applicable, the finding lifecycle must have been exercised
    (a verified/supported/proven/report_ready finding, or an honest negative).
    """
    findings = getattr(mission.context, "findings", None) or []
    supported = [
        hypothesis
        for hypothesis in mission.hypotheses
        if hypothesis.state.value in ("supported", "validated")
    ]
    applicable = bool(findings) or bool(supported)
    if not applicable:
        return CompletionGate("validation", True, "validation not applicable (no supported hypothesis/finding)")
    if findings:
        return CompletionGate("validation", True, "findings exercised through the validation lifecycle")
    return CompletionGate("validation", False, "supported hypothesis with no validation/finding recorded")


class MissionCompletionContract:
    """Objective-aware completion gates for a mission.

    Args:
        objective: the planning objective being assessed. ``None`` uses the
            full security assessment contract (the strictest default).
        coverage_target: minimum aggregate coverage required (configurable).

    """

    def __init__(self, objective: MissionObjective | str | None = None, *, coverage_target: float = 0.7) -> None:
        self._objective = objective
        self._coverage_target = coverage_target

    def objective_name(self) -> str:
        """Return the canonical objective value (``"full_security_assessment"`` default)."""
        objective = self._objective
        if objective is None:
            return "full_security_assessment"
        return objective.value if hasattr(objective, "value") else str(objective)

    def _is_full(self) -> bool:
        name = self.objective_name()
        return name in (
            MissionObjective.FULL_SECURITY_ASSESSMENT.value,
            "full_security_assessment",
        )

    def evaluate(
        self,
        mission: Any,
        *,
        pending_plan_work: bool = False,
    ) -> CompletionAssessment:
        """Evaluate every gate; ``satisfied`` only when all pass."""
        gates: list[CompletionGate] = []

        has_work = bool(mission.observations) or bool(mission.hypotheses) or mission.budget.executions_used > 0
        gates.append(
            CompletionGate("work_performed", has_work, "work performed" if has_work else "no work performed")
        )

        gates.append(
            CompletionGate(
                "no_pending_plan_work",
                not pending_plan_work,
                "no pending plan work" if not pending_plan_work else "pending plan actions remain",
            )
        )

        actionable = _actionable_open_hypotheses(mission)
        gates.append(
            CompletionGate(
                "no_actionable_open_hypotheses",
                not actionable,
                "all actionable hypotheses settled or classified"
                if not actionable
                else f"{len(actionable)} actionable hypothesis(es) still open and unclassified",
            )
        )

        coverage_ratio = mission.coverage_ratio()
        gates.append(
            CompletionGate(
                "coverage_baseline",
                coverage_ratio >= self._coverage_target,
                f"coverage {coverage_ratio:.1%} >= {self._coverage_target:.1%}"
                if coverage_ratio >= self._coverage_target
                else f"coverage {coverage_ratio:.1%} < {self._coverage_target:.1%}",
            )
        )

        # Mandatory coverage dimensions gate - prevents aggregate coverage
        # from hiding unassessed mandatory dimensions
        mandatory_satisfied, unmet = mission.mandatory_coverage_satisfied()
        gates.append(
            CompletionGate(
                "mandatory_dimensions",
                mandatory_satisfied,
                "all mandatory coverage dimensions satisfied"
                if mandatory_satisfied
                else f"mandatory dimensions unmet: {', '.join(unmet)}",
            )
        )

        gates.append(_active_testing_gate(mission))
        gates.append(_validation_gate(mission))
        gates.append(_browser_gate(mission))

        if self._is_full():
            gates.append(_attack_path_gate(mission))

        satisfied = all(gate.satisfied for gate in gates)
        return CompletionAssessment(satisfied=satisfied, gates=tuple(gates))


def contract_for_objective(
    objective: MissionObjective | str | None,
    *,
    coverage_target: float = 0.7,
) -> MissionCompletionContract:
    """Return the completion contract for ``objective``."""
    return MissionCompletionContract(objective, coverage_target=coverage_target)


__all__ = [
    "CompletionAssessment",
    "CompletionGate",
    "MissionCompletionContract",
    "contract_for_objective",
]
