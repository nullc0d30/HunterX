# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin sandbox policy.

Enforces permission boundaries around plugin execution. The policy evaluates
whether a requested permission flag is allowed for a plugin before the action
is performed; actual isolation is delegated to the configured sandbox port.
"""

from __future__ import annotations

from hunterx.domain.exceptions import SandboxError
from hunterx.plugins.manifest import PermissionFlag
from hunterx.plugins.permissions import PluginPermissions


class SandboxPolicy:
    """Evaluate permission requests against a plugin's granted set."""

    def __init__(self, platform_permissions: frozenset[PermissionFlag] | None = None) -> None:
        self._platform = platform_permissions or frozenset({PermissionFlag.NONE})

    def allow(self, plugin_name: str, permissions: PluginPermissions, flag: PermissionFlag) -> None:
        """Raise :class:`SandboxError` when ``flag`` is not allowed.

        A flag is allowed only when both the plugin's granted set and the
        platform-wide policy include it.
        """
        if flag == PermissionFlag.NONE:
            return
        if not permissions.allows(flag):
            raise SandboxError(f"Plugin '{plugin_name}' is not permitted to use '{flag.value}'.")
        if flag not in self._platform:
            raise SandboxError(f"Platform policy denies '{flag.value}' for plugin '{plugin_name}'.")
