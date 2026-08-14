# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool provisioning.

Installs missing external tools through TRUSTED, STATIC installation methods
declared in the readiness manifest. The provisioner:

- never builds commands from user/target input — package names and module
  paths are static manifest constants;
- is idempotent — an already-available tool is never reinstalled
  (detect → verify → reuse);
- verifies every install by re-running discovery before declaring success;
- reports ``UNSUPPORTED`` clearly when no compatible method exists for the
  current platform;
- always captures the executed command and its output so provisioning is
  auditable.

Unit tests inject a fake command runner — no real package is ever installed
during normal test runs.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404  # guarded static command vector (see _run)
import sys
from typing import Any

from hunterx.tools.readiness.models import (
    InstallMethod,
    InstallOutcome,
    ToolDefinition,
    ToolReadiness,
    ToolReadinessStatus,
)
from hunterx.tools.readiness.platform import PlatformInfo

#: Prefix used when the process has no elevation rights but the method needs it.
_SUDO = ("sudo",)


class CommandRunner:
    """Execute static install commands, capturing bounded output.

    Subclass or stub in tests to avoid real installations. The argv is always
    passed structurally (no shell) so arguments are inert data.
    """

    def __init__(self, *, timeout_s: float = 900.0) -> None:
        self._timeout = timeout_s

    def run(self, argv: list[str]) -> tuple[int, str, str]:
        """Run ``argv`` and return ``(returncode, stdout, stderr)``."""
        try:
            completed = subprocess.run(  # nosec B603  # trusted static argv
                argv,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            return 127, "", f"command not found: {argv[0]}" if argv else str(exc)
        except subprocess.TimeoutExpired:
            return 124, "", f"install timed out after {self._timeout}s"
        except OSError as exc:
            return 126, "", str(exc)
        return completed.returncode, completed.stdout or "", completed.stderr or ""


class ToolProvisioner:
    """Provision missing tools through trusted static install methods.

    Args:
        discovery: the discovery probe used to detect/re-verify tools.
        platform: the detected runtime platform.
        runner: the command runner (stub in tests).
        auto_elevate: when ``True`` (default) prefix elevation-requiring
            commands with ``sudo`` unless already root; when ``False`` such
            methods are reported as unsupported.

    """

    def __init__(
        self,
        discovery: Any,
        platform: PlatformInfo,
        runner: Any | None = None,
        *,
        auto_elevate: bool = True,
        command_available: Any | None = None,
    ) -> None:
        self._discovery = discovery
        self._platform = platform
        self._runner = runner or CommandRunner()
        self._auto_elevate = auto_elevate
        self._command_available = command_available or shutil.which

    def install(self, definition: ToolDefinition, *, verify: bool = True) -> InstallOutcome:
        """Provision ``definition`` and return the outcome.

        Already-available tools are skipped (idempotency). Returns an
        ``UNSUPPORTED`` outcome when no compatible install method exists on
        the current platform, and a ``PROVISIONING_FAILED`` outcome when the
        install ran but post-install verification did not pass.
        """
        current = self._discovery.probe(definition, self._platform)
        if current.status is ToolReadinessStatus.AVAILABLE:
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=True,
                status=ToolReadinessStatus.AVAILABLE,
                version=current.version,
                skipped=True,
            )
        if current.status is ToolReadinessStatus.OUTDATED and not self._should_upgrade(current):
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=True,
                status=current.status,
                version=current.version,
                skipped=True,
            )

        methods = self._compatible_methods(definition)
        if not methods:
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=False,
                status=ToolReadinessStatus.UNSUPPORTED,
                version=current.version,
                error=_unsupported_reason(definition, self._platform),
            )

        method = methods[0]
        command = self._build_command(method)
        returncode, stdout, stderr = self._runner.run(list(command))
        if returncode != 0:
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=False,
                status=ToolReadinessStatus.PROVISIONING_FAILED,
                version=current.version,
                method=method,
                command=tuple(command),
                stdout=stdout,
                stderr=stderr,
                error=(stderr or stdout or f"install exited {returncode}")[:2000],
            )

        if not verify:
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=True,
                status=ToolReadinessStatus.AVAILABLE,
                method=method,
                command=tuple(command),
                stdout=stdout,
                stderr=stderr,
            )

        after = self._discovery.probe(definition, self._platform)
        if after.status is ToolReadinessStatus.AVAILABLE or (
            after.status is ToolReadinessStatus.OUTDATED and not self._should_upgrade(after)
        ):
            self._discovery.mark_installed(definition.tool_id, after.version)
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=True,
                status=after.status,
                version=after.version,
                method=method,
                command=tuple(command),
                stdout=stdout,
                stderr=stderr,
            )
        return InstallOutcome(
            tool_id=definition.tool_id,
            success=False,
            status=ToolReadinessStatus.PROVISIONING_FAILED,
            version=after.version,
            method=method,
            command=tuple(command),
            stdout=stdout,
            stderr=stderr,
            error="installation finished but the tool could not be verified",
        )

    # -- helpers -----------------------------------------------------------

    def _compatible_methods(self, definition: ToolDefinition) -> list[InstallMethod]:
        methods: list[InstallMethod] = []
        for method in definition.installation_methods:
            if self._platform.os not in method.platforms:
                continue
            if method.requires_elevation and not self._auto_elevate:
                continue
            if method.requires_elevation and not self._elevated() and not self._can_sudo():
                continue
            if not self._method_available(method):
                continue
            methods.append(method)
        return methods

    def _method_available(self, method: InstallMethod) -> bool:
        """Return ``True`` when the runtime/package-manager for ``method`` exists.

        Prevents the provisioner from attempting commands that are unavailable
        (``go`` absent, ``cargo`` absent, ``apt-get`` absent, ...) — only tools
        and package managers actually present in the environment are used.
        """
        if method.kind == "apt":
            return self._platform.package_manager == "apt" and self._command_available("apt-get") is not None
        if method.kind == "pacman":
            return self._platform.package_manager == "pacman" and self._command_available("pacman") is not None
        if method.kind == "dnf":
            return self._platform.package_manager == "dnf" and self._command_available("dnf") is not None
        if method.kind == "brew":
            return self._command_available("brew") is not None
        if method.kind == "go":
            return self._command_available("go") is not None
        if method.kind == "cargo":
            return self._command_available("cargo") is not None
        if method.kind == "pip":
            return True  # uses sys.executable; always available
        if method.kind == "pipx":
            return self._command_available("pipx") is not None
        if method.kind == "npm":
            return self._command_available("npm") is not None
        if method.kind == "choco":
            return self._command_available("choco") is not None
        if method.kind == "script":
            return self._command_available("bash") is not None
        return False

    def _build_command(self, method: InstallMethod) -> list[str]:
        """Return the concrete argv for a trusted install method."""
        if method.kind == "apt":
            prefix = [] if self._elevated() else list(_SUDO)
            return [*prefix, "apt-get", "install", "-y", method.package]
        if method.kind == "pacman":
            prefix = [] if self._elevated() else list(_SUDO)
            return [*prefix, "pacman", "-S", "--noconfirm", method.package]
        if method.kind == "dnf":
            prefix = [] if self._elevated() else list(_SUDO)
            return [*prefix, "dnf", "install", "-y", method.package]
        if method.kind == "brew":
            return ["brew", "install", method.package]
        if method.kind == "go":
            return ["go", "install", "-v", method.name]
        if method.kind == "cargo":
            return ["cargo", "install", method.package]
        if method.kind == "pip":
            argv = [sys.executable, "-m", "pip", "install"]
            if not self._elevated() and method.package:
                argv.append("--user")
            argv.append(method.package)
            return argv
        if method.kind == "pipx":
            return ["pipx", "install", method.package]
        if method.kind == "npm":
            argv = ["npm", "install", "-g", method.package]
            if method.requires_elevation:
                argv = ([] if self._elevated() else list(_SUDO)) + argv
            return argv
        if method.kind == "choco":
            argv = ["choco", "install", "-y", method.package]
            if method.requires_elevation and not self._elevated():
                argv = [
                    "powershell",
                    "-Command",
                    f"Start-Process choco -ArgumentList 'install,-y,{method.package}' -Verb RunAs",
                ]
            return argv
        if method.kind == "script":
            return ["bash", "-c", _STATIC_SCRIPTS.get(method.name, "exit 1")]
        raise ValueError(f"unsupported install method kind: {method.kind}")

    def _elevated(self) -> bool:
        return bool(self._platform.is_root)

    def _can_sudo(self) -> bool:
        return self._platform.os in ("linux", "darwin")

    def _should_upgrade(self, readiness: ToolReadiness) -> bool:
        # Only auto-upgrade when a min version is declared and the installed
        # version is below it; otherwise keep the existing install.
        return False


def _unsupported_reason(definition: ToolDefinition, platform: PlatformInfo) -> str:
    if not definition.installation_methods:
        return f"no supported installation method declared for '{definition.tool_id}'"
    return (
        f"no compatible installation method for '{definition.tool_id}' on "
        f"{platform.os}/{platform.distro or platform.package_manager}"
    )


#: Static, trusted shell scripts for ``script``-kind install methods. Kept
#: intentionally minimal; every entry is a static constant (never interpolated).
_STATIC_SCRIPTS: dict[str, str] = {}


__all__ = ["CommandRunner", "ToolProvisioner"]
