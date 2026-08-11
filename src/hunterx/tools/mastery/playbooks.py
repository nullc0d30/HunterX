# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Data-driven tool playbooks.

Playbooks define an objective, the capabilities required to achieve it,
preferred/fallback tools, preconditions, stop conditions and evidence/
proof requirements. They never hardcode unrestricted attack commands —
concrete tool selection is delegated to the mission-aware selector at runtime.
"""

from __future__ import annotations

import threading

from hunterx.domain.tool_mastery import (
    ToolPlaybook,
    ToolPlaybookCategory,
    ToolPlaybookStep,
)

#: Canonical playbook identifiers defined by the Sprint 025 contract.
PLAYBOOK_IDS = (
    "web-initial-recon",
    "api-discovery",
    "subdomain-enumeration",
    "network-recon",
    "web-content-discovery",
    "javascript-analysis",
    "secret-discovery",
    "vulnerability-triage",
    "xss-validation",
    "sqli-validation",
    "ssrf-validation",
    "ssti-validation",
    "xxe-validation",
    "graphql-assessment",
    "cloud-assessment",
    "container-assessment",
    "active-directory-assessment",
)


class ToolPlaybookEngine:
    """Registry and query layer for data-driven playbooks."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._playbooks: dict[str, ToolPlaybook] = {}

    def register(self, playbook: ToolPlaybook) -> None:
        """Register (or replace) a playbook."""
        with self._lock:
            self._playbooks[playbook.playbook_id] = playbook

    def register_all(self, playbooks: list[ToolPlaybook]) -> None:
        """Register several playbooks at once."""
        for playbook in playbooks:
            self.register(playbook)

    def get(self, playbook_id: str) -> ToolPlaybook | None:
        """Return a playbook by id."""
        with self._lock:
            return self._playbooks.get(playbook_id)

    def list(self) -> tuple[ToolPlaybook, ...]:
        """Return every registered playbook."""
        with self._lock:
            return tuple(self._playbooks.values())

    def ids(self) -> tuple[str, ...]:
        """Return every registered playbook id."""
        with self._lock:
            return tuple(sorted(self._playbooks))

    def by_mission(self, mission_type: str) -> tuple[ToolPlaybook, ...]:
        """Return playbooks appropriate for a mission type."""
        with self._lock:
            return tuple(
                playbook
                for playbook in self._playbooks.values()
                if not playbook.mission_types or mission_type in playbook.mission_types
            )

    def by_category(self, category: ToolPlaybookCategory) -> tuple[ToolPlaybook, ...]:
        """Return playbooks in a category."""
        with self._lock:
            return tuple(
                playbook
                for playbook in self._playbooks.values()
                if playbook.category is category
            )

    def required_capabilities(self, playbook_id: str) -> tuple[str, ...]:
        """Return the union of required capabilities across a playbook's steps."""
        playbook = self.get(playbook_id)
        if playbook is None:
            return ()
        seen: list[str] = []
        for step in playbook.steps:
            for capability in step.required_capabilities:
                if capability not in seen:
                    seen.append(capability)
        return tuple(seen)

    def preferred_tools(self, playbook_id: str) -> tuple[str, ...]:
        """Return the union of preferred tools across a playbook's steps."""
        playbook = self.get(playbook_id)
        if playbook is None:
            return ()
        seen: list[str] = []
        for step in playbook.steps:
            for tool in step.preferred_tools:
                if tool not in seen:
                    seen.append(tool)
        return tuple(seen)


def build_playbook(
    playbook_id: str,
    *,
    name: str,
    category: ToolPlaybookCategory,
    objective: str,
    mission_types: tuple[str, ...] = (),
    steps: list[ToolPlaybookStep] | None = None,
    stop_conditions: tuple[str, ...] = (),
    description: str = "",
) -> ToolPlaybook:
    """Build a :class:`ToolPlaybook` from its parts."""
    return ToolPlaybook(
        playbook_id=playbook_id,
        name=name,
        category=category,
        objective=objective,
        mission_types=mission_types,
        steps=tuple(steps or []),
        stop_conditions=stop_conditions,
        description=description,
    )


def build_step(
    step_id: str,
    *,
    objective: str,
    required_capabilities: tuple[str, ...] = (),
    preferred_tools: tuple[str, ...] = (),
    fallback_tools: tuple[str, ...] = (),
    preconditions: tuple[str, ...] = (),
    stop_conditions: tuple[str, ...] = (),
    evidence_requirements: tuple[str, ...] = (),
    proof_requirements: tuple[str, ...] = (),
    safety_class: str = "passive",
) -> ToolPlaybookStep:
    """Build a :class:`ToolPlaybookStep` from its parts."""
    return ToolPlaybookStep(
        step_id=step_id,
        objective=objective,
        required_capabilities=required_capabilities,
        preferred_tools=preferred_tools,
        fallback_tools=fallback_tools,
        preconditions=preconditions,
        stop_conditions=stop_conditions,
        evidence_requirements=evidence_requirements,
        proof_requirements=proof_requirements,
        safety_class=safety_class,
    )
