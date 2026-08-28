# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Generic attack-workflow representation.

Phase 2. Multi-step target behavior is represented generically as

    State A → Action → State B → Action → State C

with security properties evaluated at each transition. Workflows are built from
discovered workflow/state-transition surfaces — never hardcoded application
workflows. Each transition carries the capability ids whose security property
applies at that step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class AttackWorkflowState:
    """A single state in an attack workflow.

    Attributes:
        state_id: stable state identifier.
        name: state name.
        properties: free-form state attributes.

    """

    state_id: str = field(default_factory=generate_id)
    name: str = ""
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {"state_id": self.state_id, "name": self.name, "properties": dict(self.properties)}


@dataclass(frozen=True, slots=True)
class AttackWorkflowTransition:
    """A single State A → Action → State B transition.

    Attributes:
        transition_id: stable transition identifier.
        from_state: source :class:`AttackWorkflowState`.
        to_state: target :class:`AttackWorkflowState`.
        action: the action that moves the workflow forward.
        security_properties: capability ids to evaluate at this transition.

    """

    transition_id: str = field(default_factory=generate_id)
    from_state: str = ""
    to_state: str = ""
    action: str = ""
    security_properties: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "transition_id": self.transition_id,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "action": self.action,
            "security_properties": list(self.security_properties),
        }


@dataclass(slots=True)
class AttackWorkflow:
    """A generic workflow represented as states and transitions.

    Attributes:
        workflow_id: stable workflow identifier.
        name: workflow name.
        source_surface_key: the surface node the workflow was discovered from.
        mission_id / target_key: owning context.
        states: states keyed by name.
        transitions: ordered transitions.
        created_at: UTC ISO-8601 stamp.

    """

    workflow_id: str = field(default_factory=generate_id)
    name: str = ""
    source_surface_key: str = ""
    mission_id: str = ""
    target_key: str = ""
    states: dict[str, AttackWorkflowState] = field(default_factory=dict)
    transitions: list[AttackWorkflowTransition] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)

    def add_state(self, name: str, properties: dict[str, Any] | None = None) -> AttackWorkflowState:
        """Add a state (idempotent by name) and return it."""
        state = self.states.get(name)
        if state is None:
            state = AttackWorkflowState(name=name, properties=dict(properties or {}))
            self.states[name] = state
        return state

    def add_transition(
        self,
        *,
        from_state: str,
        to_state: str,
        action: str = "",
        security_properties: tuple[str, ...] = (),
    ) -> AttackWorkflowTransition:
        """Add a State A → Action → State B transition."""
        transition = AttackWorkflowTransition(
            from_state=from_state,
            to_state=to_state,
            action=action,
            security_properties=tuple(security_properties),
        )
        self.transitions.append(transition)
        return transition

    def state_names(self) -> list[str]:
        """Return the state names in insertion order."""
        return list(self.states)

    def security_properties(self) -> set[str]:
        """Return the union of capability ids to evaluate across transitions."""
        return {property_id for transition in self.transitions for property_id in transition.security_properties}

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "source_surface_key": self.source_surface_key,
            "mission_id": self.mission_id,
            "target_key": self.target_key,
            "states": [state.to_dict() for state in self.states.values()],
            "transitions": [transition.to_dict() for transition in self.transitions],
            "security_properties": sorted(self.security_properties()),
            "created_at": self.created_at,
        }


def build_workflow_from_attributes(
    *,
    name: str,
    attributes: dict[str, Any],
    source_surface_key: str = "",
    mission_id: str = "",
    target_key: str = "",
    security_properties: tuple[str, ...] = (),
) -> AttackWorkflow:
    """Build an :class:`AttackWorkflow` from discovered workflow attributes.

    ``attributes`` may carry ``steps`` (a flat state list) or ``transitions``
    (a list of ``{"from": ..., "to": ..., "action": ...}`` dicts). Unknown
    shapes degrade to a single-state workflow rather than failing.
    """
    workflow = AttackWorkflow(
        name=name,
        source_surface_key=source_surface_key,
        mission_id=mission_id,
        target_key=target_key,
    )
    transitions = attributes.get("transitions")
    if isinstance(transitions, list) and transitions:
        for transition in transitions:
            if not isinstance(transition, dict):
                continue
            from_state = str(transition.get("from") or transition.get("from_state") or "")
            to_state = str(transition.get("to") or transition.get("to_state") or "")
            if not from_state and not to_state:
                continue
            if from_state:
                workflow.add_state(from_state)
            if to_state:
                workflow.add_state(to_state)
            if from_state and to_state:
                workflow.add_transition(
                    from_state=from_state,
                    to_state=to_state,
                    action=str(transition.get("action") or ""),
                    security_properties=security_properties,
                )
        if workflow.transitions:
            return workflow
    steps = attributes.get("steps")
    if isinstance(steps, list) and steps:
        previous = ""
        for step in steps:
            name = str(step.get("name") if isinstance(step, dict) else step or "").strip()
            if not name:
                continue
            workflow.add_state(name)
            if previous:
                workflow.add_transition(
                    from_state=previous,
                    to_state=name,
                    action="advance",
                    security_properties=security_properties,
                )
            previous = name
        if workflow.transitions:
            return workflow
    workflow.add_state(workflow.name or "initial")
    return workflow


__all__ = ["AttackWorkflow", "AttackWorkflowState", "AttackWorkflowTransition", "build_workflow_from_attributes"]
