# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Master profile registry.

Stores the complete, authoritative per-tool :class:`ToolMasterProfile`
records together with the arsenal-level relationship graph, playbooks,
datasets and mission models. Thread-safe, keyed by ``tool_id``.
"""

from __future__ import annotations

import threading

from hunterx.domain.exceptions.operation import ToolNotFoundError, ToolRegistrationError
from hunterx.domain.tool_intelligence import ToolMetadata
from hunterx.domain.tool_mastery import ToolMasterProfile, ToolSupportLevel


class ToolMasteryRegistry:
    """Registry of tool master profiles.

    A master profile is the aggregate of everything HunterX knows about a
    tool. Registration requires a valid :class:`ToolMasterProfile` whose
    ``tool_id`` matches its embedded metadata.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._profiles: dict[str, ToolMasterProfile] = {}

    # -- registration -----------------------------------------------------

    def register(self, profile: ToolMasterProfile) -> None:
        """Register (or replace) a tool master profile."""
        if not profile.tool_id:
            raise ToolRegistrationError("master profile requires a tool_id")
        if profile.metadata.tool_id != profile.tool_id:
            raise ToolRegistrationError(
                f"profile tool_id '{profile.tool_id}' does not match metadata "
                f"tool_id '{profile.metadata.tool_id}'"
            )
        with self._lock:
            self._profiles[profile.tool_id] = profile

    def unregister(self, tool_id: str) -> bool:
        """Remove a profile; returns ``True`` when it existed."""
        with self._lock:
            return self._profiles.pop(tool_id, None) is not None

    def clear(self) -> None:
        """Remove every profile (used by tests and resets)."""
        with self._lock:
            self._profiles.clear()

    # -- queries ----------------------------------------------------------

    def get(self, tool_id: str) -> ToolMasterProfile | None:
        """Return the profile for ``tool_id`` or ``None``."""
        with self._lock:
            return self._profiles.get(tool_id)

    def require(self, tool_id: str) -> ToolMasterProfile:
        """Return the profile for ``tool_id`` or raise :class:`ToolNotFoundError`."""
        profile = self.get(tool_id)
        if profile is None:
            raise ToolNotFoundError(tool_id)
        return profile

    def list(self) -> tuple[ToolMasterProfile, ...]:
        """Return every registered profile."""
        with self._lock:
            return tuple(self._profiles.values())

    def tool_ids(self) -> tuple[str, ...]:
        """Return every registered tool id."""
        with self._lock:
            return tuple(sorted(self._profiles))

    def metadata(self, tool_id: str) -> ToolMetadata | None:
        """Return the metadata embedded in a profile, or ``None``."""
        profile = self.get(tool_id)
        return profile.metadata if profile is not None else None

    def support_level(self, tool_id: str) -> ToolSupportLevel | None:
        """Return the support classification of ``tool_id``."""
        profile = self.get(tool_id)
        return profile.support_level if profile is not None else None

    def by_support_level(self, level: ToolSupportLevel) -> tuple[str, ...]:
        """Return tool ids classified at ``level``."""
        with self._lock:
            return tuple(
                sorted(
                    tool_id
                    for tool_id, profile in self._profiles.items()
                    if profile.support_level is level
                )
            )

    def providers_of(self, capability_id: str) -> tuple[str, ...]:
        """Return tool ids that provide ``capability_id``."""
        with self._lock:
            return tuple(
                sorted(
                    tool_id
                    for tool_id, profile in self._profiles.items()
                    if capability_id in profile.capability_ids
                    or capability_id in profile.knowledge.capabilities
                )
            )

    def to_dict(self) -> dict[str, object]:
        """Dump the registry to plain dictionaries."""
        return {
            "tools": {
                tool_id: _profile_to_dict(profile)
                for tool_id, profile in sorted(self._profiles.items())
            }
        }


def _profile_to_dict(profile: ToolMasterProfile) -> dict[str, object]:
    """Serialize a profile into a JSON-compatible dictionary."""
    return {
        "tool_id": profile.tool_id,
        "display_name": profile.metadata.display_name,
        "support_level": profile.support_level.value,
        "capabilities": list(profile.capability_ids or profile.knowledge.capabilities),
        "supported_targets": list(profile.supported_targets),
        "supported_protocols": list(profile.supported_protocols),
        "structured_output_formats": list(profile.structured_output_formats),
        "parser_id": profile.parser_id,
        "normalizer_id": profile.normalizer_id,
        "adapter_id": profile.adapter_id,
        "version_constraints": list(profile.version_constraints),
        "alternative_tools": list(profile.alternative_tools),
        "complementary_tools": list(profile.complementary_tools),
        "recommended_predecessors": list(profile.recommended_predecessors),
        "recommended_successors": list(profile.recommended_successors),
        "safety_class": profile.safety_class,
        "destructive": profile.destructive,
    }
