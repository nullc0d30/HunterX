# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Compatibility validator for Tool Integration Packs.

Builds the compatibility matrix for a pack, checks a tool version against a
HunterX version under the SemVer compatibility rule, and reports deprecation
status. Incompatible or malformed declarations produce a
:class:`CompatibilityError`.
"""

from __future__ import annotations

from hunterx.domain.exceptions import CompatibilityError
from hunterx.domain.tool_factory import (
    CompatibilityEntry,
    CompatibilityMatrix,
    SemanticVersion,
    ToolPackSpec,
)
from hunterx.shared.result import Failure, Result, Success
from hunterx.tools.factory.layout import HUNTERX_VERSION


class CompatibilityValidator:
    """Validates pack version compatibility against HunterX."""

    def __init__(
        self,
        *,
        hunterx_version: str = HUNTERX_VERSION,
        supported_hunterx: tuple[str, ...] = (),
    ) -> None:
        self._hunterx_version = hunterx_version
        self._supported = tuple(supported_hunterx) or (hunterx_version,)

    def build_matrix(self, spec: ToolPackSpec) -> CompatibilityMatrix:
        """Build the declared compatibility matrix for ``spec``."""
        entries: list[CompatibilityEntry] = []
        for hunterx_version in spec.hunterx_versions or self._supported:
            entries.append(
                CompatibilityEntry(
                    tool_version=spec.version,
                    hunterx_version=hunterx_version,
                    status="deprecated" if spec.deprecated else "compatible",
                    notes=spec.deprecation_reason if spec.deprecated else "",
                )
            )
        return CompatibilityMatrix(spec.pack_id, tuple(entries))

    def is_compatible(self, spec: ToolPackSpec, *, hunterx_version: str | None = None) -> bool:
        """Return ``True`` when ``spec`` is compatible with a HunterX version.

        A pack is compatible when the given HunterX version is compatible with
        at least one declared supported HunterX version (``spec.hunterx_versions``
        or the validator's supported set) under the SemVer rule. A deprecated
        pack is never compatible.
        """
        if spec.deprecated:
            return False
        target = SemanticVersion.parse(hunterx_version or self._hunterx_version)
        supported = [SemanticVersion.parse(value) for value in spec.hunterx_versions or self._supported]
        return any(target.is_compatible_with(supported_version) for supported_version in supported)

    def check(self, spec: ToolPackSpec, *, hunterx_version: str | None = None) -> Result[bool, Exception]:
        """Validate compatibility, returning a :class:`Result`.

        Malformed versions produce a :class:`CompatibilityError` failure.
        """
        try:
            return Success(self.is_compatible(spec, hunterx_version=hunterx_version))
        except ValueError as exc:
            return Failure(CompatibilityError(f"invalid version declaration: {exc}"))

    def status(self, spec: ToolPackSpec, *, hunterx_version: str | None = None) -> str:
        """Return ``compatible``, ``deprecated`` or ``incompatible``."""
        if spec.deprecated:
            return "deprecated"
        try:
            return "compatible" if self.is_compatible(spec, hunterx_version=hunterx_version) else "incompatible"
        except ValueError:
            return "incompatible"
