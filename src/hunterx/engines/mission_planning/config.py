# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission configuration resolver.

Merges configuration from every layer of a mission request and renders
``{{ variable }}`` placeholders. Precedence, lowest to highest:

1. Phase variables (profile defaults)
2. Template variables
3. Request configuration (``request.config``)
4. Request variables (``request.variables``)
5. Environment overrides (``MISSION_<KEY>``)

Values support ``{{ name }}`` interpolation and can reference environment
values through ``{{ env.VAR }}``. The resolver is strict: an unresolved
placeholder raises :class:`MissionPlanningError` so plans never ship with
holes.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from typing import Any

from hunterx.domain.exceptions import MissionPlanningError
from hunterx.domain.mission_planning import MissionPhase, MissionProfile, MissionRequest, MissionTemplate

_PLACEHOLDER = re.compile(r"\{\{\s*([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)?)\s*\}\}")

#: Default environment prefix mapping ``MISSION_<KEY>`` to a variable ``key``.
DEFAULT_ENV_PREFIX = "MISSION_"


class ConfigurationResolver:
    """Merge and render mission configuration from layered sources."""

    def __init__(
        self,
        environment: Mapping[str, str] | None = None,
        *,
        env_prefix: str = DEFAULT_ENV_PREFIX,
    ) -> None:
        self._environment = dict(environment if environment is not None else os.environ)
        self._env_prefix = env_prefix

    # -- resolution --------------------------------------------------------

    def resolve(
        self,
        profile: MissionProfile,
        request: MissionRequest,
        template: MissionTemplate | None = None,
        *,
        phase: MissionPhase | None = None,
    ) -> dict[str, object]:
        """Return the fully merged, rendered configuration for a request."""
        merged: dict[str, object] = {}
        if phase is not None:
            merged.update(phase.variables)
        if template is not None:
            merged.update(template.variables)
        merged.update(request.config)
        merged.update(request.variables)
        merged.update(self._environment_overrides())
        return self.render_mapping(merged)

    def _environment_overrides(self) -> dict[str, str]:
        """Collect ``<prefix><KEY>`` environment entries as ``key`` variables."""
        overrides: dict[str, str] = {}
        for name, value in self._environment.items():
            if name.upper().startswith(self._env_prefix):
                key = name[len(self._env_prefix) :].lower()
                overrides[key] = value
        return overrides

    # -- rendering ---------------------------------------------------------

    def render(self, value: str, variables: Mapping[str, object]) -> str:
        """Render every ``{{ name }}`` placeholder in ``value``.

        ``{{ env.VAR }}`` reads directly from the process environment.
        Unknown placeholders raise :class:`MissionPlanningError`.
        """

        def substitute(match: re.Match[str]) -> str:
            name = match.group(1)
            if name.startswith("env."):
                env_name = name[4:]
                if env_name not in self._environment:
                    raise MissionPlanningError(
                        f"environment variable '{env_name}' referenced by a mission is not set."
                    )
                return self._environment[env_name]
            if name not in variables:
                raise MissionPlanningError(
                    f"mission configuration references undefined variable '{name}'."
                )
            return str(variables[name])

        return _PLACEHOLDER.sub(substitute, value)

    def render_value(self, value: object, variables: Mapping[str, object]) -> object:
        """Recursively render placeholders in strings, lists and mappings."""
        if isinstance(value, str):
            return self.render(value, variables)
        if isinstance(value, list):
            return [self.render_value(item, variables) for item in value]
        if isinstance(value, dict):
            return {key: self.render_value(item, variables) for key, item in value.items()}
        return value

    def render_mapping(self, mapping: Mapping[str, object]) -> dict[str, object]:
        """Render every placeholder in a mapping of nested values."""
        return {key: self.render_value(value, mapping) for key, value in mapping.items()}

    def has_placeholders(self, value: str) -> bool:
        """Return ``True`` when ``value`` still contains an unrendered placeholder."""
        return bool(_PLACEHOLDER.search(value))

    def required_variables(self, value: str) -> list[str]:
        """Return the placeholder names referenced by ``value`` in order."""
        return [match.group(1) for match in _PLACEHOLDER.finditer(value)]

    @staticmethod
    def deep_merge(base: Mapping[str, object], override: Mapping[str, object]) -> dict[str, object]:
        """Recursively merge ``override`` into ``base`` (override wins)."""
        merged: dict[str, Any] = dict(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = ConfigurationResolver.deep_merge(merged[key], value)
            else:
                merged[key] = value
        return merged
