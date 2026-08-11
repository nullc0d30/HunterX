# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Health checker.

Verifies that a tool is installed, its recorded version matches the expected
requirement, and an adapter-supplied health probe reports it functional.
Health results drive the pipeline's ``verify`` phase and gate execution.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from hunterx.domain.exceptions import ToolHealthError
from hunterx.tools.sdk.installer import InstallationManager
from hunterx.tools.sdk.version import VersionManager


@dataclass(slots=True)
class HealthResult:
    """Health verdict for one tool.

    Attributes:
        tool_id: the tool under check.
        healthy: ``True`` when the tool may execute.
        reason: human readable explanation of the verdict.
        version: version verified against.

    """

    tool_id: str
    healthy: bool
    reason: str
    version: str | None = None


HealthProbe = Callable[[str], bool]


class HealthChecker:
    """Combine installation, version and probe checks into one verdict.

    Usage::

        checker = HealthChecker(installer, versions)
        checker.probe("nmap", lambda _: shutil.which("nmap") is not None)
        ok = checker.check("nmap", requirement=">=7.80").healthy
    """

    def __init__(self, installer: InstallationManager, versions: VersionManager) -> None:
        self._installer = installer
        self._versions = versions
        self._probes: dict[str, HealthProbe] = {}

    def probe(self, tool_id: str, probe: HealthProbe) -> None:
        """Register a health probe for ``tool_id``."""
        self._probes[tool_id] = probe

    def check(self, tool_id: str, *, requirement: str | None = None) -> HealthResult:
        """Return the combined health verdict for ``tool_id``.

        A tool is healthy when it is installed, its version satisfies the
        requirement (when given) and, if a probe is registered, the probe
        reports ``True``.
        """
        if not self._installer.is_installed(tool_id):
            return HealthResult(tool_id=tool_id, healthy=False, reason="not installed")
        version = self._versions.installed(tool_id)
        if requirement and not self._versions.satisfies(tool_id, requirement):
            return HealthResult(
                tool_id=tool_id,
                healthy=False,
                reason=f"version {version!r} does not satisfy {requirement!r}",
                version=version,
            )
        probe = self._probes.get(tool_id)
        if probe is not None:
            try:
                functional = probe(tool_id)
            except Exception as error:  # noqa: BLE001 - probe failures are health verdicts
                return HealthResult(tool_id=tool_id, healthy=False, reason=f"probe error: {error}", version=version)
            if not functional:
                return HealthResult(tool_id=tool_id, healthy=False, reason="probe reported unhealthy", version=version)
        return HealthResult(tool_id=tool_id, healthy=True, reason="ok", version=version)

    def assert_healthy(self, tool_id: str, *, requirement: str | None = None) -> None:
        """Raise :class:`ToolHealthError` when the tool is not healthy."""
        result = self.check(tool_id, requirement=requirement)
        if not result.healthy:
            raise ToolHealthError(tool_id, result.reason)

    def healthy_tools(self) -> list[str]:
        """Return the tool ids currently reported healthy."""
        return [tool_id for tool_id in self._installer.installed_tools() if self.check(tool_id).healthy]
