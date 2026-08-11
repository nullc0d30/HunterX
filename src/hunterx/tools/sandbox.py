# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool sandbox policy.

Restricts what a tool may do at runtime based on its declared permissions and
the platform-wide policy, mirroring the plugin sandbox model.
"""

from __future__ import annotations

from hunterx.domain.exceptions import SandboxError
from hunterx.domain.tools import ToolDescriptor
from hunterx.plugins.manifest import PermissionFlag


class ToolSandboxPolicy:
    """Evaluate tool permission requests against granted platform flags."""

    def __init__(self, platform_permissions: frozenset[PermissionFlag] | None = None) -> None:
        self._platform = platform_permissions or frozenset({PermissionFlag.NONE})

    def allow(self, descriptor: ToolDescriptor, flag: PermissionFlag) -> None:
        """Raise :class:`SandboxError` when the tool lacks permission.

        A permission is granted when it appears in the tool's descriptor
        ``permissions`` and the platform policy includes it.
        """
        if flag == PermissionFlag.NONE:
            return
        if flag.value not in descriptor.permissions:
            raise SandboxError(f"Tool '{descriptor.name}' lacks permission '{flag.value}'.")
        if flag not in self._platform:
            raise SandboxError(f"Platform policy denies '{flag.value}' for tool '{descriptor.name}'.")
