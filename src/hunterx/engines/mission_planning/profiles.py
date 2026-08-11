# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission profile and template engine.

Registers and resolves :class:`~hunterx.domain.mission_planning.MissionProfile`
and :class:`~hunterx.domain.mission_planning.MissionTemplate` records.
Profiles support inheritance: a profile declaring a ``parent`` inherits every
field its parent does not override, and child phases override same-id parent
phases. Template resolution binds a template to its profile so the
configuration resolver can merge variables and overrides.
"""

from __future__ import annotations

from hunterx.domain.exceptions import (
    MissionPlanningError,
    MissionProfileNotFoundError,
    MissionTemplateNotFoundError,
)
from hunterx.domain.mission_planning import (
    MissionApprovalLevel,
    MissionPhase,
    MissionProfile,
    MissionTemplate,
)
from hunterx.domain.ports.mission_planning import (
    MissionProfileRepository,
    MissionTemplateRepository,
)


def merge_profiles(parent: MissionProfile, child: MissionProfile) -> MissionProfile:
    """Return a new profile inheriting ``parent`` fields the child overrides.

    Phase merge semantics: child phases override same-id parent phases; child
    phase order is preserved, followed by parent-only phases in parent order.
    Dict fields (allowed_tools, expected_outputs, risk_model, constraints) are
    merged key-by-key; list fields are child-first unions.
    """
    phases = _merge_phases(parent.phases, child.phases)
    allowed_tools = _merge_mapping(parent.allowed_tools, child.allowed_tools)
    expected_outputs = _merge_mapping(parent.expected_outputs, child.expected_outputs)
    risk_model = _merge_mapping(parent.risk_model, child.risk_model)
    constraints = _merge_mapping(parent.constraints, child.constraints)
    return MissionProfile(
        profile_id=child.profile_id,
        name=child.name,
        description=child.description or parent.description,
        version=child.version or parent.version,
        mission_types=child.mission_types or parent.mission_types,
        phases=phases,
        objectives=child.objectives or parent.objectives,
        allowed_tools=allowed_tools,
        expected_outputs=expected_outputs,
        approval_level=(
            child.approval_level
            if child.approval_level is not MissionApprovalLevel.OPERATOR
            else parent.approval_level
        ),
        risk_model=risk_model,
        constraints=constraints,
        compliance_map=child.compliance_map or parent.compliance_map,
        parent=parent.profile_id,
    )


def _merge_phases(parent: tuple[MissionPhase, ...], child: tuple[MissionPhase, ...]) -> tuple[MissionPhase, ...]:
    """Merge phase tuples: child wins by id, parent-only phases appended."""
    if not child:
        return parent
    by_id = {phase.phase_id: phase for phase in parent}
    merged = [child_phase for child_phase in child]
    for phase_id in by_id:
        if phase_id not in {child_phase.phase_id for child_phase in child}:
            merged.append(by_id[phase_id])
    return tuple(merged)


def _merge_mapping(parent: dict[str, object], child: dict[str, object]) -> dict[str, object]:
    """Merge two plain mappings, child values winning per key."""
    merged = dict(parent)
    for key, value in child.items():
        if key in merged and isinstance(merged[key], list) and isinstance(value, list):
            merged[key] = [*value, *[item for item in merged[key] if item not in value]]
        else:
            merged[key] = value
    return merged


class MissionProfileEngine:
    """Register profiles/templates and resolve inheritance and templates.

    When no repositories are supplied the engine keeps in-process stores,
    which is the default for embedded use and unit tests.
    """

    def __init__(
        self,
        profiles: MissionProfileRepository | None = None,
        templates: MissionTemplateRepository | None = None,
    ) -> None:
        self._profiles = profiles
        self._templates = templates
        self._profile_store: dict[str, MissionProfile] = {}
        self._template_store: dict[str, MissionTemplate] = {}

    # -- profile registration ----------------------------------------------

    def register_profile(self, profile: MissionProfile) -> MissionProfile:
        """Register a profile, detecting cycles in its inheritance chain.

        Parents that are not yet registered are tolerated so profiles may be
        loaded in any order; unknown parents surface as
        :class:`MissionProfileNotFoundError` when the chain is resolved.
        """
        self._profile_store[profile.profile_id] = profile
        try:
            if profile.parent is not None:
                self._resolve_chain(profile.parent, (profile.profile_id,))
        except Exception:
            del self._profile_store[profile.profile_id]
            raise
        if self._profiles is not None:
            self._profiles.save(profile)
        return profile

    def _resolve_chain(self, profile_id: str, visited: tuple[str, ...]) -> None:
        """Walk a profile's parent chain.

        Raises on cycles among registered profiles, tolerating ancestors that
        are not registered yet.
        """
        if profile_id in visited:
            raise MissionPlanningError(
                f"profile inheritance cycle: {' -> '.join((*visited, profile_id))}"
            )
        profile = self.get_profile(profile_id)
        if profile is None:
            return
        if profile.parent is not None:
            self._resolve_chain(profile.parent, (*visited, profile_id))

    def get_profile(self, profile_id: str) -> MissionProfile | None:
        """Return the raw (unmerged) profile, or ``None``."""
        profile = self._profile_store.get(profile_id)
        if profile is None and self._profiles is not None:
            profile = self._profiles.get(profile_id)
            if profile is not None:
                self._profile_store[profile_id] = profile
        return profile

    def resolve_profile(self, profile_id: str) -> MissionProfile:
        """Return the fully merged profile for ``profile_id``.

        Resolves the inheritance chain, raising
        :class:`MissionProfileNotFoundError` for unknown parents and
        :class:`MissionPlanningError` for inheritance cycles.
        """
        return self._resolve(profile_id, visited=())

    def _resolve(self, profile_id: str, visited: tuple[str, ...]) -> MissionProfile:
        if profile_id in visited:
            raise MissionPlanningError(
                f"profile inheritance cycle: {' -> '.join((*visited, profile_id))}"
            )
        profile = self.get_profile(profile_id)
        if profile is None:
            raise MissionProfileNotFoundError(profile_id)
        if profile.parent is None:
            return profile
        parent = self._resolve(profile.parent, (*visited, profile_id))
        return merge_profiles(parent, profile)

    def list_profiles(self) -> list[MissionProfile]:
        """Return every registered raw profile."""
        if self._profiles is not None and not self._profile_store:
            self._profile_store = {p.profile_id: p for p in self._profiles.list(limit=10_000)}
        return list(self._profile_store.values())

    # -- template registration ---------------------------------------------

    def register_template(self, template: MissionTemplate) -> MissionTemplate:
        """Register a template, validating its profile resolves."""
        self.resolve_profile(template.profile_id)
        self._template_store[template.template_id] = template
        if self._templates is not None:
            self._templates.save(template)
        return template

    def get_template(self, template_id: str) -> MissionTemplate | None:
        """Return a template, or ``None``."""
        template = self._template_store.get(template_id)
        if template is None and self._templates is not None:
            template = self._templates.get(template_id)
            if template is not None:
                self._template_store[template_id] = template
        return template

    def resolve_template(self, template_id: str) -> MissionTemplate:
        """Return a template, raising :class:`MissionTemplateNotFoundError`."""
        template = self.get_template(template_id)
        if template is None:
            raise MissionTemplateNotFoundError(template_id)
        return template

    def list_templates(self) -> list[MissionTemplate]:
        """Return every registered template."""
        if self._templates is not None and not self._template_store:
            self._template_store = {t.template_id: t for t in self._templates.list(limit=10_000)}
        return list(self._template_store.values())
