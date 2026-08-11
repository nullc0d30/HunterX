# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Installation manager.

Installs and uninstalls tool binaries through an adapter-provided installer
hook. This module is intentionally thin: it does not ship or run any tool —
actual installation is delegated to the tool adapter's ``installer`` callable
so the SDK never embeds vendor-specific knowledge.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from hunterx.domain.exceptions import ToolInstallationError
from hunterx.shared.time import utcnow_iso


@dataclass(slots=True)
class InstallationRecord:
    """A completed or attempted installation.

    Attributes:
        tool_id: the tool being installed.
        version: the installed version.
        installed_at: ISO timestamp of the successful install.
        error: error message when the installation failed.
        attempts: number of attempts made.

    """

    tool_id: str
    version: str = ""
    installed_at: str | None = None
    error: str | None = None
    attempts: int = 0


InstallHook = Callable[[str, str | None], str]


class InstallationManager:
    """Delegate tool installation to adapter hooks and track state.

    Usage::

        installer = InstallationManager()
        installer.register("nmap", lambda tool, version: "7.94")
        installer.install("nmap")
        installer.is_installed("nmap")   # True
    """

    def __init__(self) -> None:
        self._hooks: dict[str, InstallHook] = {}
        self._records: dict[str, InstallationRecord] = {}

    def register(self, tool_id: str, hook: InstallHook) -> None:
        """Register the installation hook for ``tool_id``."""
        self._hooks[tool_id] = hook

    def is_installed(self, tool_id: str) -> bool:
        """Return ``True`` when the tool has a successful installation record."""
        record = self._records.get(tool_id)
        return record is not None and record.error is None and record.installed_at is not None

    def install(self, tool_id: str, version: str | None = None, *, attempt: int = 0) -> InstallationRecord:
        """Run the registered installation hook for ``tool_id``.

        Raises:
            ToolInstallationError: when no hook is registered or the hook fails.

        """
        hook = self._hooks.get(tool_id)
        if hook is None:
            raise ToolInstallationError(
                tool_id,
                reason=f"no installation hook registered for '{tool_id}'",
            )
        record = self._records.get(tool_id) or InstallationRecord(tool_id=tool_id)
        record.attempts = attempt + 1
        try:
            installed_version = hook(tool_id, version)
        except Exception as error:  # noqa: BLE001 - installer errors are reported, not propagated
            record.error = str(error)
            self._records[tool_id] = record
            raise ToolInstallationError(tool_id, reason=str(error)) from error
        record.version = installed_version
        record.installed_at = utcnow_iso()
        record.error = None
        self._records[tool_id] = record
        return record

    def uninstall(self, tool_id: str) -> None:
        """Drop the installation record for ``tool_id``."""
        self._records.pop(tool_id, None)

    def record_for(self, tool_id: str) -> InstallationRecord | None:
        """Return the installation record, or ``None``."""
        return self._records.get(tool_id)

    def installed_tools(self) -> list[str]:
        """Return the tool ids with a successful installation."""
        return [tool_id for tool_id, record in self._records.items() if record.error is None]
