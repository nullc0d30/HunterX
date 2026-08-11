# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Version resolution for Tool Integration Packs.

Helpers over :class:`SemanticVersion` for sorting, constraint satisfaction,
compatibility ranges and the deprecation policy every pack carries.
"""

from __future__ import annotations

from hunterx.domain.tool_factory import SemanticVersion, ToolPackSpec


class VersionResolver:
    """Semantic version helpers for the Tool Integration Factory."""

    @staticmethod
    def parse(versions: list[str]) -> list[SemanticVersion]:
        """Parse every version string, preserving order."""
        return [SemanticVersion.parse(value) for value in versions]

    @staticmethod
    def sort(versions: list[str], *, reverse: bool = False) -> list[str]:
        """Return ``versions`` ordered semantically (ascending by default)."""
        return sorted(versions, key=SemanticVersion.parse, reverse=reverse)

    @staticmethod
    def latest(versions: list[str]) -> str | None:
        """Return the highest version, or ``None`` when empty."""
        if not versions:
            return None
        return str(max(SemanticVersion.parse(value) for value in versions))

    @staticmethod
    def satisfies(version: str, constraint: str) -> bool:
        """Return ``True`` when ``version`` satisfies ``constraint``."""
        return SemanticVersion.parse(version).satisfies(constraint)

    @staticmethod
    def is_stable(version: str) -> bool:
        """Return ``True`` for a stable 1.0+ version."""
        return SemanticVersion.parse(version).is_stable

    @staticmethod
    def deprecation_plan(spec: ToolPackSpec) -> dict[str, object]:
        """Return the deprecation plan declared by ``spec``.

        A deprecated pack stays usable but is removed on the next major
        release; every migration is recorded in ``metadata/migrations.yaml``.
        """
        if not spec.deprecated:
            return {
                "deprecated": False,
                "reason": "",
                "removal": None,
                "migration_path": "not required",
            }
        return {
            "deprecated": True,
            "reason": spec.deprecation_reason,
            "removal": "next major release",
            "migration_path": "see metadata/migrations.yaml",
        }
