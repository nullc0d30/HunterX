# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin permission model."""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.plugins.manifest import PermissionFlag


@dataclass(frozen=True, slots=True)
class PluginPermissions:
    """The effective permission set granted to a loaded plugin.

    The manager derives this from the manifest and the platform policy; a
    plugin may never request more than its manifest declared.
    """

    granted: frozenset[PermissionFlag] = field(default_factory=lambda: frozenset({PermissionFlag.NONE}))

    def allows(self, flag: PermissionFlag) -> bool:
        """Return ``True`` when ``flag`` (or its fallback) is granted."""
        if flag == PermissionFlag.NONE:
            return True
        return flag in self.granted

    @classmethod
    def from_manifest(cls, requested: tuple[PermissionFlag, ...]) -> PluginPermissions:
        """Derive a permission set from a manifest's request."""
        return cls(frozenset(requested))
